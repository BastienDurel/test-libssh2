#include <memory>

#define BOOST_TEST_MODULE test_libssh2
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
// extracted with: ssh-keygen -f fake_rsa -p -m pem
const char* pkey_pem =
  "-----BEGIN RSA PRIVATE KEY-----\n"
  "MIICXQIBAAKBgQC/pbM6bmUa9ZZJArrpw8Bpv3Ue2zdR7w8q5dMSiSQNqfr7yufq\n"
  "t23ulFB8pqPQ0+VezcfWjw6V2ZRlVQzfOTiDrc809r3qyQrHS7e4nz84VB3TRp/7\n"
  "ZO97SB0FMu5mSDIVyHc2bsaGokm+C/gAJK1vIt6A1uQLblfZ3PXGSN534wIDAQAB\n"
  "AoGAWxu3HOwmfK6MB6GYolFBRASU9VpZ7kWr/ETOF13DGgvZGaLYpikVxfoUWW4P\n"
  "KtPRk0RY4JOZ53tMpO/N8sENMBgnQQ4PsI31CcWtGpSt+TGkm6zfHtANqzplb874\n"
  "Tb1+wQpo8/gmdaKAglM8VpwOr7u1PCdbD/xopAc5tIxKP0ECQQD8XvLQNVmTBCCt\n"
  "RFwZB4j7YC2QxjjIUgDHiJUiRBXmrbLHva2g1+jJJ3crmOvhS0tlThzLQO4wqTni\n"
  "CqZqutlpAkEAwmc1yCI7L1dGhtyIhLN6oZ/swaB50YbfPRlEevSvlNnirlgQiRbD\n"
  "5m1nWdu6XnzlHAPzqzZUj2q36IgZNlSxawJBALj9RFE4egNY6Db5v+Sc8F0K3/ua\n"
  "QS8dZPLd/CtU6xTfSAg/0lDvUvR4GFN90ZGgZpDIlDSs0Kwcr5AwrFHZytkCQQCs\n"
  "JNqyAuXn0N/J8iUNZST1U/lBqEnW6RhrMSG7w0prg9k/ywmxazBDrqMzJehNXUk/\n"
  "2pv+A1kzuitqRIIW4z5LAkAHPro7mrQo+xnsPwhvS5e3cb32JUt57bQBtJcIyRZx\n"
  "ytHeD/JXkzC6PGRP1LPGRCAEI/IMiAZzhZiM0d2cwura\n"
  "-----END RSA PRIVATE KEY-----\n";
// extracted with: openssl rsa -in fake_rsa.pem -noout -text
const char* pubkey_pem =
  "-----BEGIN PUBLIC KEY-----\n"
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/pbM6bmUa9ZZJArrpw8Bpv3Ue\n"
  "2zdR7w8q5dMSiSQNqfr7yufqt23ulFB8pqPQ0+VezcfWjw6V2ZRlVQzfOTiDrc80\n"
  "9r3qyQrHS7e4nz84VB3TRp/7ZO97SB0FMu5mSDIVyHc2bsaGokm+C/gAJK1vIt6A\n"
  "1uQLblfZ3PXGSN534wIDAQAB\n"
  "-----END PUBLIC KEY-----\n";
// extracted with: ssh-keygen -f fake_rsa -e -m pem
const char* pubkey_pem_2 =
  "-----BEGIN RSA PUBLIC KEY-----\n"
  "MIGJAoGBAL+lszpuZRr1lkkCuunDwGm/dR7bN1HvDyrl0xKJJA2p+vvK5+q3be6U\n"
  "UHymo9DT5V7Nx9aPDpXZlGVVDN85OIOtzzT2verJCsdLt7ifPzhUHdNGn/tk73tI\n"
  "HQUy7mZIMhXIdzZuxoaiSb4L+AAkrW8i3oDW5AtuV9nc9cZI3nfjAgMBAAE=\n"
  "-----END RSA PUBLIC KEY-----\n";


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
  BOOST_CHECK_EQUAL(test_pubkey(pubkey, pkey, nullptr), expected);
  BOOST_CHECK_EQUAL(test_pubkey(pubkey, pkey_pp, keypass), expected);
  BOOST_CHECK_EQUAL(test_pubkey(pubkey, pkey_pem, nullptr), expected);
  BOOST_CHECK_EQUAL(test_pubkey(ed_pubkey, ed_pkey, nullptr), expected);
  BOOST_CHECK_EQUAL(test_pubkey(ed_pubkey, ed_pkey_pp, keypass), expected);
}


BOOST_AUTO_TEST_CASE( ssh_failures ) {
  // Incorrect pubkey: should fail with LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED
  BOOST_CHECK_EQUAL(test_pubkey(ed_pubkey, pkey, nullptr),
                    LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED);
  // wrong formats
  BOOST_CHECK_EQUAL(test_pubkey(pubkey_pem, pkey, nullptr),
                    LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED);
  BOOST_CHECK_EQUAL(test_pubkey(pubkey_pem, pkey_pem, nullptr),
                    LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED);
  BOOST_CHECK_EQUAL(test_pubkey(pubkey_pem_2, pkey_pem, nullptr),
                    LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED);
}
