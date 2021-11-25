#include <cstring>
#include <iostream>
#include <fstream>
#include <thread>
#include <boost/asio.hpp>

#include "ssh.hpp"
#include "test.hpp"
#include "utils.hpp"

#include <boost/log/trivial.hpp>

remote_t remote{ getenv("TEST_HOST"), getenv("TEST_PORT") };

remote_t::remote_t(const char* h, const char* p) {
  host = h ? h : "localhost";
  port = p ? p : "22";
}

static std::string type2string(int type) {
  switch (type) {
    case LIBSSH2_HOSTKEY_TYPE_RSA:
      return "rsa";
    case LIBSSH2_HOSTKEY_TYPE_DSS:
      return "dss";
#if defined LIBSSH2_HOSTKEY_TYPE_ECDSA_256
    case LIBSSH2_HOSTKEY_TYPE_ECDSA_256:
      return "ecdsa(256)";
    case LIBSSH2_HOSTKEY_TYPE_ECDSA_384:
      return "ecdsa(384)";
    case LIBSSH2_HOSTKEY_TYPE_ECDSA_521:
      return "ecdsa(521)";
#endif
#if defined LIBSSH2_HOSTKEY_TYPE_ED25519
    case LIBSSH2_HOSTKEY_TYPE_ED25519:
      return "ed25519";
#endif
    case LIBSSH2_HOSTKEY_TYPE_UNKNOWN:
      return "unknown";
    default:
      break;
  }
  return std::to_string(type);
}

static void write(int fd, const std::string& data) {
  ssize_t rc = ::write(fd, data.data(), data.size());
  if (rc < data.size()) {
    int count = 0;
    ssize_t wr = 0;
    do {
      if (rc < 0)
        THROW("Cannot write into file");
      wr += rc;
      if (rc == 0 && ++count > 25) --rc;
      rc = ::write(fd, data.data() + wr, data.size() - wr);
    } while (rc < data.size() - wr);
  }
  ::write(fd, "\n", 1);
  ::close(fd);
}

static std::string ssh2_err(LIBSSH2_SESSION* session) {
  char* msg;
  int len;
  libssh2_session_last_error(session, &msg, &len, 0);
  std::string res;
  res.reserve(len + 3);
  return res.append(" (", 2).append(msg, len).append(")", 1);
}

static bool sshInit = false;
static std::mutex sMutex;
LIBSSH2_SESSION *make_session(void) {
  if (!sshInit) {
    std::lock_guard _lock(sMutex);
    if (!sshInit) {
      int rc;
#if defined _WIN32 || defined _WIN64
      WSADATA wsadata;

      rc = WSAStartup(MAKEWORD(2, 0), &wsadata);
      if (rc != 0)
        THROW("WSAStartup failed with error: " + std::to_string(rc));
#endif
      rc = libssh2_init(0);
      if (rc != 0)
        THROW("libssh2 initialization failed: " + std::to_string(rc));
      sshInit = true;
    }
  }
  LIBSSH2_SESSION* session = libssh2_session_init();
  if (!session)
    THROW("session initialization failed");
  // tell libssh2 we want it all done non-blocking
  libssh2_session_set_blocking(session, 0);
  return session;
}

// If libssh2 is not built against openssl,
// libssh2_userauth_publickey_frommemory fails, therefore we have to write
// key material in tempfiles and use libssh2_userauth_publickey_fromfile
static int _auth_pukey_mem2file(LIBSSH2_SESSION *session,
                                const std::string& username,
                                const std::string& pubkeydata,
                                const std::string& keydata,
                                const char* keypass) {
  using namespace boost::filesystem;
  std::string base = (temp_directory_path() /
                      unique_path("ssh-tmp-key-%%%%-%%%%-%%%%-%%%%.XXXXXX"))
    .string();
#if defined HAVE_MKSTEMP
  std::string pub_{ base }, priv_{ base };
  int pub_fd = mkstemp(pub_.data());
  int priv_fd = mkstemp(priv_.data());
#else
  std::string pub_{ base + ".pub" }, priv_{ base };
#endif
  BOOST_LOG_TRIVIAL(debug) << "Writing key material into "
                           << pub_ << " & " << priv_;
  unlinkable pubkey(pub_), privkey(priv_);
#if defined HAVE_MKSTEMP
  write(pub_fd, pubkeydata);
  write(priv_fd, keydata);
#else
  std::ofstream{ pub_ } << pubkeydata << std::endl;
  std::ofstream{ priv_ } << keydata << std::endl;
#endif
  int rc;
  do {
    rc = libssh2_userauth_publickey_fromfile(session, username.c_str(),
                                             pubkey.fn().c_str(),
                                             privkey.fn().c_str(),
                                             keypass
      );
  } while (rc == LIBSSH2_ERROR_EAGAIN);
  switch (rc) {
    case LIBSSH2_ERROR_AUTHENTICATION_FAILED:
      BOOST_LOG_TRIVIAL(debug) << "LIBSSH2_ERROR_AUTHENTICATION_FAILED";
      break;
    case LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED:
      BOOST_LOG_TRIVIAL(debug) << "LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED";
      break;
    case LIBSSH2_ERROR_ALLOC:
      BOOST_LOG_TRIVIAL(debug) << "LIBSSH2_ERROR_ALLOC";
      break;
    case LIBSSH2_ERROR_SOCKET_SEND:
      BOOST_LOG_TRIVIAL(debug) << "LIBSSH2_ERROR_SOCKET_SEND";
      break;
    case LIBSSH2_ERROR_SOCKET_TIMEOUT:
      BOOST_LOG_TRIVIAL(debug) << "LIBSSH2_ERROR_SOCKET_TIMEOUT";
      break;
    default: break;
  }
  //exec{ "cat", pubkey.fn() }.run();
  //exec{ "cat", privkey.fn() }.run();
  //std::cout << keypass << std::endl;
  //int k; (std::cerr << "Enter key: ").flush(); std::cin >> k;
  return rc;
}

static int auth_pukey_mem(LIBSSH2_SESSION *session, const std::string& username,
                          const std::string& pubkeydata,
                          const std::string& keydata,
                          const char* keypass) {
  BOOST_LOG_TRIVIAL(debug) << "Using provided key data for user "
                           << username;
#if defined HAVE_LIBSSH2_CRYPTOENGINE_API
  if (libssh2_crypto_engine() != libssh2_crypto_engine_t::libssh2_openssl)
    return _auth_pukey_mem2file(session, username, pubkeydata, keydata,
                                keypass);
#endif
  bool first_log = true;
  int rc;
  do {
    if (first_log) {
      first_log = false;
      BOOST_LOG_TRIVIAL(trace) << "pubkey: " << sview(pubkeydata)
                               << " - privkey: " << sview(keydata);
    }
    rc = libssh2_userauth_publickey_frommemory(session,
                                               username.c_str(),
                                               username.size(),
                                               pubkeydata.data(),
                                               pubkeydata.size(),
                                               keydata.data(),
                                               keydata.size(),
                                               keypass);
  } while (rc == LIBSSH2_ERROR_EAGAIN);
  switch (rc) {
    case LIBSSH2_ERROR_AUTHENTICATION_FAILED:
      BOOST_LOG_TRIVIAL(debug) << "LIBSSH2_ERROR_AUTHENTICATION_FAILED";
      break;
    case LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED:
      BOOST_LOG_TRIVIAL(debug) << "LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED";
      break;
    case LIBSSH2_ERROR_ALLOC:
      BOOST_LOG_TRIVIAL(debug) << "LIBSSH2_ERROR_ALLOC";
      break;
    case LIBSSH2_ERROR_SOCKET_SEND:
      BOOST_LOG_TRIVIAL(debug) << "LIBSSH2_ERROR_SOCKET_SEND";
        break;
    case LIBSSH2_ERROR_SOCKET_TIMEOUT:
      BOOST_LOG_TRIVIAL(debug) << "LIBSSH2_ERROR_SOCKET_TIMEOUT";
      break;
    default: break;
  }
#if !defined HAVE_LIBSSH2_CRYPTOENGINE_API
  // We don't know if openssl is built in or not. If not, we must
  // write keys into temporary files
  if (rc == LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED)
    rc = _auth_pukey_mem2file(session, username, pubkeydata, keydata,
                              keypass);
#endif
  // Do not throw, as we want to test return value
  //if (rc)
  //THROW("Authentication by public key failed: " + ssh2_err(session));
  return rc;
}

int test_pubkey(const std::string& username, const std::string& pubkeydata,
                const std::string& keydata, const char* keypass) {
  LIBSSH2_SESSION *session = make_session();
  libssh2_trace(session,
                LIBSSH2_TRACE_KEX | LIBSSH2_TRACE_PUBLICKEY |
                LIBSSH2_TRACE_ERROR);
  return _test_pubkey(session, username, pubkeydata, keydata, keypass);
}

using namespace boost::filesystem;

int _test_pubkey(LIBSSH2_SESSION *session, const std::string& username,
                 const std::string& pubkeydata, const std::string& keydata,
                 const char* keypass) {
  using tcp = boost::asio::ip::tcp;
  boost::asio::io_context io_context;
  tcp::resolver r(io_context);
  tcp::socket s(io_context);
  boost::asio::connect(s, r.resolve(remote.host, remote.port));
  auto_close_sock _s(s);
  
  ssize_t rc;
  while ((rc = libssh2_session_handshake(session, s.native_handle())) == LIBSSH2_ERROR_EAGAIN);
  if (rc)
    THROW("Failure establishing SSH session: " + ssh2_err(session));

  LIBSSH2_KNOWNHOSTS* nh = libssh2_knownhost_init(session);
  if (!nh)
    THROW("Cannot init knownhost");
  auto_del<LIBSSH2_KNOWNHOSTS, void, libssh2_knownhost_free> _nh(nh);

  // read all hosts from here
  path kh_file = home() / ".ssh" / "known_hosts";
  if (exists(kh_file))
    libssh2_knownhost_readfile(nh, kh_file.string().c_str(),
                               LIBSSH2_KNOWNHOST_FILE_OPENSSH);
  kh_file = home() / ".ssh" / "known_hosts2";
  if (exists(kh_file))
    libssh2_knownhost_readfile(nh, kh_file.string().c_str(),
                               LIBSSH2_KNOWNHOST_FILE_OPENSSH);
#if !defined _WIN32 && !defined _WIN64
  kh_file = "/etc/ssh/ssh_known_hosts";
  if (exists(kh_file))
    libssh2_knownhost_readfile(nh, kh_file.string().c_str(),
                               LIBSSH2_KNOWNHOST_FILE_OPENSSH);
  kh_file = "/etc/ssh/ssh_known_hosts2";
  if (exists(kh_file))
    libssh2_knownhost_readfile(nh, kh_file.string().c_str(),
                               LIBSSH2_KNOWNHOST_FILE_OPENSSH);
#endif

  size_t len = 0;
  int type;
  const char *fingerprint = libssh2_session_hostkey(session, &len, &type);
  if (!fingerprint)
    THROW("Cannot get fingerprint: " + ssh2_err(session));
  BOOST_LOG_TRIVIAL(trace) << "fingerprint type " << type2string(type)
                           << ": " << base64dump(fingerprint, len);
  struct libssh2_knownhost *host;
  int check = libssh2_knownhost_checkp(nh, remote.host.c_str(), remote.portn(),
                                       fingerprint, len,
                                       LIBSSH2_KNOWNHOST_TYPE_PLAIN|LIBSSH2_KNOWNHOST_KEYENC_RAW,
                                       &host);
  // At this point, we could verify that 'check' tells us the key is fine or bail out.
  BOOST_LOG_TRIVIAL(trace) << "libssh2_knownhost_checkp returned " << check;
  if (remote.check_host) {
    switch (check) {
      case LIBSSH2_KNOWNHOST_CHECK_FAILURE:
        THROW("Cannot check host against known hosts");
      case LIBSSH2_KNOWNHOST_CHECK_NOTFOUND:
        if (!remote.allow_unknown)
          THROW("Unknown host fingerprint");
        else
          BOOST_LOG_TRIVIAL(debug) << "Unknown host fingerprint, ignoring";
        break;
      case LIBSSH2_KNOWNHOST_CHECK_MISMATCH:
        BOOST_LOG_TRIVIAL(info) << "You may need to run `ssh-keyscan "
                                << "-t <type> >> ~/.ssh/known_hosts "
                                << remote.host << "` to allow key";
        THROW("Host fingerprint mismatch!");
      case LIBSSH2_KNOWNHOST_CHECK_MATCH:
        BOOST_LOG_TRIVIAL(debug) << "Host key matches with known_hosts";
    }
  }
    
  return auth_pukey_mem(session, username, pubkeydata, keydata, keypass);
}
