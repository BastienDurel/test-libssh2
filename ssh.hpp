#if !defined TEST_SSH_HPP_INCLUDED
#define TEST_SSH_HPP_INCLUDED

#include <libssh2.h>

LIBSSH2_SESSION *make_session(void);

int test_pubkey(const std::string& pubkeydata, const std::string& keydata,
                const char* keypass);
int _test_pubkey(LIBSSH2_SESSION *session, const std::string& pubkeydata,
                 const std::string& keydata, const char* keypass);

struct remote_t {
  std::string host, port, username;
  bool check_host = true;
  bool allow_unknown = false;
  remote_t(const char* h, const char* p, const char* u);
  int portn() const { return atoi(port.c_str()); }
};
extern remote_t remote;

std::string ssh2_err(LIBSSH2_SESSION* session);

static inline const std::string known_retvals(int rc) {
  switch (rc) {
    case LIBSSH2_ERROR_AUTHENTICATION_FAILED:
      return "LIBSSH2_ERROR_AUTHENTICATION_FAILED";
    case LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED:
      return "LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED";
    case LIBSSH2_ERROR_ALLOC:
      return "LIBSSH2_ERROR_ALLOC";
    case LIBSSH2_ERROR_SOCKET_SEND:
      return "LIBSSH2_ERROR_SOCKET_SEND";
    case LIBSSH2_ERROR_SOCKET_TIMEOUT:
      return "LIBSSH2_ERROR_SOCKET_TIMEOUT";
    default: break;
  }
  return std::to_string(rc);
}

// print human-readable rc in debug log
void debug_rc(int rc);

#endif// TEST_SSH_HPP_INCLUDED
