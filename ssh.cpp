#include <cstring>
#include <iostream>
#include <fstream>
#include <thread>
#include <boost/asio.hpp>

#include "ssh.hpp"
#include "test.hpp"
#include "utils.hpp"

#include <boost/log/trivial.hpp>

remote_t remote(getenv("TEST_HOST"), getenv("TEST_PORT"), getenv("TEST_USER"));

remote_t::remote_t(const char* h, const char* p, const char* u) {
  host = h ? h : "localhost";
  port = p ? p : "22";
  username = u ? u : "test";
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

std::string openssh2pem(const std::string& keydata);
bool is_openssh(const std::string& keydata);

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
#if TEST_CONVERT
  std::string keydata_ = is_openssh(keydata) ? openssh2pem(keydata) : keydata;
#else
  std::string& keydata_ = keydata;
#endif
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
  write(priv_fd, keydata_);
#else
  std::ofstream{ pub_ } << pubkeydata << std::endl;
  std::ofstream{ priv_ } << keydata_ << std::endl;
#endif
  int rc;
  do {
    rc = libssh2_userauth_publickey_fromfile(session, username.c_str(),
                                             pubkey.fn().c_str(),
                                             privkey.fn().c_str(),
                                             keypass
      );
  } while (rc == LIBSSH2_ERROR_EAGAIN);
  debug_rc(rc);
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
  debug_rc(rc);
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

int test_pubkey(const std::string& pubkeydata, const std::string& keydata,
                const char* keypass) {
  LIBSSH2_SESSION *session = make_session();
  libssh2_trace(session,
                LIBSSH2_TRACE_KEX | LIBSSH2_TRACE_PUBLICKEY |
                LIBSSH2_TRACE_ERROR);
  return _test_pubkey(session, pubkeydata, keydata, keypass);
}

#if defined TEST_WITH_KH_FP
void _check_kh_fp(LIBSSH2_SESSION *session);
#endif

int _test_pubkey(LIBSSH2_SESSION *session, const std::string& pubkeydata,
                 const std::string& keydata, const char* keypass) {
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
#if defined TEST_WITH_KH_FP
  _check_kh_fp(session);
#endif
  // Test pubkey function
  return auth_pukey_mem(session, remote.username, pubkeydata, keydata, keypass);
}
