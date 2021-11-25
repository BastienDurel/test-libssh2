#include <memory>

#define BOOST_TEST_MODULE agent
#include <boost/test/unit_test.hpp>
#include <boost/test/results_collector.hpp>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>

#include "ssh.hpp"

// Initialize application (set logger level, setup exec destructor handler)
struct auto_init {
  auto_init() {
    namespace logging = boost::log;
    auto lvl = getenv("TRACE") ?
      logging::trivial::trace : (
        getenv("QUIET") ? logging::trivial::info : logging::trivial::debug);
    logging::core::get()->set_filter
      (
        logging::trivial::severity >= lvl
        );
  }
};
static std::unique_ptr<auto_init> _auto_init_instance(new auto_init);

const char* pubkey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC/pbM6bmUa9ZZJArrpw8Bpv3Ue2zdR7w8q5dMSiSQNqfr7yufqt23ulFB8pqPQ0+VezcfWjw6V2ZRlVQzfOTiDrc809r3qyQrHS7e4nz84VB3TRp/7ZO97SB0FMu5mSDIVyHc2bsaGokm+C/gAJK1vIt6A1uQLblfZ3PXGSN534w== bastien@data-bastien";
const char* pkey =
  "-----BEGIN OPENSSH PRIVATE KEY-----\n"
  "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn\n"
  "NhAAAAAwEAAQAAAIEAv6WzOm5lGvWWSQK66cPAab91Hts3Ue8PKuXTEokkDan6+8rn6rdt\n"
  "7pRQfKaj0NPlXs3H1o8OldmUZVUM3zk4g63PNPa96skKx0u3uJ8/OFQd00af+2Tve0gdBT\n"
  "LuZkgyFch3Nm7GhqJJvgv4ACStbyLegNbkC25X2dz1xkjed+MAAAIQ++iZQvvomUIAAAAH\n"
  "c3NoLXJzYQAAAIEAv6WzOm5lGvWWSQK66cPAab91Hts3Ue8PKuXTEokkDan6+8rn6rdt7p\n"
  "RQfKaj0NPlXs3H1o8OldmUZVUM3zk4g63PNPa96skKx0u3uJ8/OFQd00af+2Tve0gdBTLu\n"
  "ZkgyFch3Nm7GhqJJvgv4ACStbyLegNbkC25X2dz1xkjed+MAAAADAQABAAAAgFsbtxzsJn\n"
  "yujAehmKJRQUQElPVaWe5Fq/xEzhddwxoL2Rmi2KYpFcX6FFluDyrT0ZNEWOCTmed7TKTv\n"
  "zfLBDTAYJ0EOD7CN9QnFrRqUrfkxpJus3x7QDas6ZW/O+E29fsEKaPP4JnWigIJTPFacDq\n"
  "+7tTwnWw/8aKQHObSMSj9BAAAAQAc+ujuatCj7Gew/CG9Ll7dxvfYlS3nttAG0lwjJFnHK\n"
  "0d4P8leTMLo8ZE/Us8ZEIAQj8gyIBnOFmIzR3ZzC6toAAABBAPxe8tA1WZMEIK1EXBkHiP\n"
  "tgLZDGOMhSAMeIlSJEFeatsse9raDX6MkndyuY6+FLS2VOHMtA7jCpOeIKpmq62WkAAABB\n"
  "AMJnNcgiOy9XRobciISzeqGf7MGgedGG3z0ZRHr0r5TZ4q5YEIkWw+ZtZ1nbul585RwD86\n"
  "s2VI9qt+iIGTZUsWsAAAAUYmFzdGllbkBkYXRhLWJhc3RpZW4BAgMEBQYH\n"
  "-----END OPENSSH PRIVATE KEY-----\n";
const char* pkey_pp =
  "-----BEGIN OPENSSH PRIVATE KEY-----\n"
  "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAuI9r4r7\n"
  "2Jc+Yp+4pg+5R0AAAAEAAAAAEAAACXAAAAB3NzaC1yc2EAAAADAQABAAAAgQC/pbM6bmUa\n"
  "9ZZJArrpw8Bpv3Ue2zdR7w8q5dMSiSQNqfr7yufqt23ulFB8pqPQ0+VezcfWjw6V2ZRlVQ\n"
  "zfOTiDrc809r3qyQrHS7e4nz84VB3TRp/7ZO97SB0FMu5mSDIVyHc2bsaGokm+C/gAJK1v\n"
  "It6A1uQLblfZ3PXGSN534wAAAhCWSLCDq75Uq9R+wAlKa//fjEw6NWdy0D7rP4kU/79c3Y\n"
  "YVFxHBZvwOXFEDdN6Mud1olrUcnmVFJ64ULrBi3asJvj5rmGkJTcSJUecQz3Ee2uMCQjcV\n"
  "caw8us4m6e7m8LOTsHR8Bu3eo3CBf48U91XNTIJw90GBkI6Vwv7mqTib+IViMVt81T5Jms\n"
  "j9PpsgKIJdpj5n+XnVIOttDRUM/jwTTyl39Os7iBun3+9yVPS3jDT2kWgJYQkzAxSXcpE7\n"
  "yeSIcz1N+7rgdo3Nrx0MgQdBwMRoFekFhr00ARTJwUlbnL7bLOOoWMk9BrH7tsy58t0o6F\n"
  "Wx0Tvf49lVlDMkvHbk5FvqHLTrNP7NNc6QArsSO9K3Mem5TbVbccafpKjWdzUwfiU6sKqd\n"
  "QB/CTAlitKuvbo+Sa/BfMwkgi2H6ksiKT+9a0ndaUSsvXKLQM7+E9HwbXDTICTD34iimU2\n"
  "1NVQdHJq5fSB1KOk8OIemW7L0GVy4hXIehgff6zUVZYDwcQKegQn2QI9lVWVs3XK7De7Fg\n"
  "4QCKJ6STI+CS0Cd98j3BGc6kRE7B2cr6NF/PH0s+caNXjzLLgpNr5AqCzA2BJWdZm/bIU4\n"
  "vonInLpCpzqOjAG/teEk0JgCqUxenq2x1I9tZqHeDdREbTPPT/C6bcOx8SmQ1fcMG54GXd\n"
  "LQ7psS5/Cs6hqr3Lrua87gT5P/W5WKw=\n"
  "-----END OPENSSH PRIVATE KEY-----\n";
const char* keypass = "foobar";

// ed25519 key
const char* ed_pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID40+qudR9CqU+XV5hJ4pJ7WNXY297Fq0TpsMUu+YAiW bastien@data-bastien";
const char* ed_pkey =
  "-----BEGIN OPENSSH PRIVATE KEY-----\n"
  "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
  "QyNTUxOQAAACA+NPqrnUfQqlPl1eYSeKSe1jV2NvexatE6bDFLvmAIlgAAAJhM4qCITOKg\n"
  "iAAAAAtzc2gtZWQyNTUxOQAAACA+NPqrnUfQqlPl1eYSeKSe1jV2NvexatE6bDFLvmAIlg\n"
  "AAAEBiQs6nor8u+4hvWGxiGhfn5QT/MYfC9VEyWzMr7hoadT40+qudR9CqU+XV5hJ4pJ7W\n"
  "NXY297Fq0TpsMUu+YAiWAAAAFGJhc3RpZW5AZGF0YS1iYXN0aWVuAQ==\n"
  "-----END OPENSSH PRIVATE KEY-----\n";
const char* ed_pkey_pp =
  "-----BEGIN OPENSSH PRIVATE KEY-----\n"
  "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBrfn+/5h\n"
  "EKycuniiL47Y0JAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAID40+qudR9CqU+XV\n"
  "5hJ4pJ7WNXY297Fq0TpsMUu+YAiWAAAAoDHfvrpUeKFCp7sb+Hr8iz/NnzM6ZbfuolePf+\n"
  "rLSnUN67RaVCTBigKIDKAUuDjkv4ZwAIpr5z45Qwq0h+sR19Woti2NrksRcdb6ZLDX3Ynx\n"
  "0Ntru67j2VqlSg1uE0G202P85ySiJUR9w+bvr+UQvto2bEleIDxrKzADaRhBkjsjrnHu9q\n"
  "l6mRNXfTtatFrqDYTsJCmkVUVoHWq4gn+9X3Y=\n"
  "-----END OPENSSH PRIVATE KEY-----\n";

BOOST_AUTO_TEST_CASE( ssh ) {
  remote.check_host = false;
  BOOST_WARN_MESSAGE(remote.host != "localhost", "Testing with localhost!");
  BOOST_WARN_MESSAGE(remote.username == "test", "Testing with user: "
                     + remote.username);
  int expected = 0;
  if (getenv("TEST_EXPECTED")) {
    expected = atoi(getenv("TEST_EXPECTED"));
    BOOST_TEST_MESSAGE("expected return value set to: " +
                       known_retvals(expected));
  }
  int rc = test_pubkey(pubkey, pkey, nullptr);
  BOOST_CHECK_EQUAL(rc, expected);
  rc = test_pubkey(pubkey, pkey_pp, keypass);
  BOOST_CHECK_EQUAL(rc, expected);
  rc = test_pubkey(ed_pubkey, ed_pkey, nullptr);
  BOOST_CHECK_EQUAL(rc, expected);
  rc = test_pubkey(ed_pubkey, ed_pkey_pp, keypass);
  BOOST_CHECK_EQUAL(rc, expected);
  // Incorrect pubkey: should fail with LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED
  rc = test_pubkey(ed_pubkey, pkey, nullptr);
  BOOST_CHECK_EQUAL(rc, LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED);
}
