#include <cstring>
#include <iostream>
#include <fstream>
#include <thread>
#include <boost/asio.hpp>

#include "ssh.hpp"
#include "test.hpp"
#include "utils.hpp"

#include <boost/log/trivial.hpp>

using namespace boost::filesystem;

std::string ssh2_err(LIBSSH2_SESSION* session) {
  char* msg;
  int len;
  libssh2_session_last_error(session, &msg, &len, 0);
  std::string res;
  res.reserve(len + 3);
  return res.append(" (", 2).append(msg, len).append(")", 1);
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

void _check_kh_fp(LIBSSH2_SESSION *session) {
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
}
