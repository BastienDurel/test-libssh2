#if !defined TEST_SSH_HPP_INCLUDED
#define TEST_SSH_HPP_INCLUDED

#include <libssh2.h>
#include <boost/filesystem.hpp>

LIBSSH2_SESSION *make_session(void);

int test_pubkey(const std::string& username, const std::string& pubkeydata,
                const std::string& keydata, const char* keypass);
int _test_pubkey(LIBSSH2_SESSION *session, const std::string& username,
                 const std::string& pubkeydata, const std::string& keydata,
                 const char* keypass);

struct remote_t {
  std::string host, port;
  bool check_host = true;
  bool allow_unknown = false;
  remote_t(const char* h, const char* p);
  int portn() const { return atoi(port.c_str()); }
};
extern remote_t remote;

boost::filesystem::path home();

#endif// TEST_SSH_HPP_INCLUDED
