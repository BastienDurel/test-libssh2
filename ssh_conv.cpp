#include <cstring>
#include <iostream>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/insert_linebreaks.hpp>
#include <boost/archive/iterators/remove_whitespace.hpp>

#include "ssh.hpp"
#include "test.hpp"
#include "utils.hpp"

#include <boost/log/trivial.hpp>

static const std::string openssh_key{ "-----BEGIN OPENSSH PRIVATE KEY-----" },
  openssh_key_end{ "-----END OPENSSH PRIVATE KEY-----" };
bool is_openssh(const std::string& keydata) {
  return keydata.find(openssh_key) == 0;
}

static std::string decode(std::string input)
{
  using namespace boost::archive::iterators;
  typedef transform_width<binary_from_base64<remove_whitespace
      <std::string::const_iterator> >, 8, 6> ItBinaryT;

  try
  {
    // If the input isn't a multiple of 4, pad with =
    size_t num_pad_chars((4 - input.size() % 4) % 4);
    input.append(num_pad_chars, '=');

    size_t pad_chars(std::count(input.begin(), input.end(), '='));
    std::replace(input.begin(), input.end(), '=', 'A');
    std::string output(ItBinaryT(input.begin()), ItBinaryT(input.end()));
    output.erase(output.end() - pad_chars, output.end());
    return output;
  }
  catch (std::exception const&)
  {
    return std::string("");
  }
}

static inline char _x(int i) {
    return i + ((i < 0xa) ? '0' : 'a' - 0xa);
}

template <int BLOCK = 16>
static void xd(const std::string& s) {
  size_t off = 0;
  char offset[8] = "[   ] ";
  do {
    std::string row = s.substr(off, BLOCK);
    off += BLOCK;
    std::string hex, asc;
    size_t i;
    for (i = 0; i < row.size(); ++i) {
      if (std::isprint(row[i]))
        asc.append(1, row[i]);
      else
        asc.append(1, '.');
      unsigned x = row[i];
      hex.append(1, _x((x & 0xf0) >> 4));
      hex.append(1, _x(x & 0xf));
      hex.append(1, ' ');
    }
    while (i++ < BLOCK)
      hex.append("   ");
    sprintf(offset, "[%.4x] ", off);
    BOOST_LOG_TRIVIAL(debug) << offset << hex << "\t" << asc;
  } while (off < s.size());
}

static void handle_pubkey(const std::string& pubkey);
static void handle_privkey(const std::string& data);
static std::string decipher(const std::string& data,
                            const std::string& cipher,
                            const std::string& kdfname,
                            const std::string& kdfopts,
                            const char* key);

#define GETLEN(l) do { if ((off + sizeof(uint32_t)) > data.size()) THROW("Cannot extract data from openssh keydata: cannot read length out of buffer"); const uint32_t *len_ = reinterpret_cast<const uint32_t*>((unsigned char*)(d) + off); l = ntohl(*len_); off += sizeof(uint32_t); } while (0)
#define CHECK_OFF(x)  BOOST_LOG_TRIVIAL(debug) << x " len: " << len; if ((off + len) > data.size()) THROW("Cannot extract data from openssh keydata: invalid length")

std::string openssh2pem(const std::string& keydata) {
  BOOST_LOG_TRIVIAL(debug) << "Trying to convert " << sview(keydata);
  std::istringstream i{ keydata };
  char buf[76];
  bool in_header = false;
  std::string data, datab;
  while (!i.eof()) {
    i.getline(buf, 72);
    if (i.fail())
      THROW("Cannot extract data from openssh keydata");
    if (openssh_key == buf)
      continue;
    if (openssh_key_end == buf)
      break;
    if (in_header) {
      std::string hdr{ buf };
      BOOST_LOG_TRIVIAL(debug) << " -cont: " << hdr;
      in_header = hdr.back() == '\\';
      continue;
    }
    if (strchr(buf, ':')) {
      std::string hdr{ buf };
      BOOST_LOG_TRIVIAL(debug) << "header: " << hdr;
      in_header = hdr.back() == '\\';
      continue;
    }
    datab.append(buf);
    BOOST_LOG_TRIVIAL(trace) << "buf: " << buf;
  }
  data = decode(datab);
  xd(data);
  BOOST_LOG_TRIVIAL(debug) << "decoded: " << sview(data, 14)
                           << " (" << data.size() << ")";
  if (data.compare(0, 14, "openssh-key-v1"))
    THROW("Cannot extract data from openssh keydata: unknown format");
  const void* d = data.data();
  ssize_t off = 15;
  uint32_t len, keynum;
  GETLEN(len);
  CHECK_OFF("cipher");
  std::string cipher{ data.data() + off, len };
  off += len;
  BOOST_LOG_TRIVIAL(debug) << "cipher: " << cipher;
  GETLEN(len);
  CHECK_OFF("kdfname");
  std::string kdfname{ data.data() + off, len };
  off += len;
  BOOST_LOG_TRIVIAL(debug) << "kdfname: " << kdfname;
  GETLEN(len);
  CHECK_OFF("kdfoptions");
  std::string kdfoptions{ data.data() + off, len };
  off += len;
  BOOST_LOG_TRIVIAL(debug) << "kdfoptions: " << kdfoptions;
  GETLEN(keynum);
  if (keynum != 1)
    THROW("Cannot extract data from openssh keydata: key# != 1: " + std::to_string(keynum));
  GETLEN(len);
  CHECK_OFF("pubkey");
  std::string pubkey{ data.data() + off, len };
  off += len;
  handle_pubkey(pubkey);
  GETLEN(len);
  CHECK_OFF("privkey");
  std::string privkey{ data.data() + off, len };
  off += len;
  BOOST_LOG_TRIVIAL(debug) << "privkey: " << privkey.size() << " bytes";
  if (cipher != "none")
    privkey = decipher(privkey, cipher, kdfname, kdfoptions, "");
  handle_privkey(privkey);
  return keydata;
}

static void handle_pubkey(const std::string& data) {
  const void* d = data.data();
  ssize_t off = 0;
  uint32_t len;
  GETLEN(len);
  CHECK_OFF(" - keytype");
  std::string keytype{ data.data() + off, len };
  off += len;
  BOOST_LOG_TRIVIAL(debug) << " - keytype: " << keytype;
  if (keytype == "ssh-rsa") {
    GETLEN(len);
    CHECK_OFF(" - pub0");
    std::string pub0{ data.data() + off, len };
    off += len;
    BOOST_LOG_TRIVIAL(debug) << " - pub0: " << pub0.size();
    xd(pub0);
    GETLEN(len);
    CHECK_OFF(" - pub1");
    std::string pub1{ data.data() + off, len };
    off += len;
    BOOST_LOG_TRIVIAL(debug) << " - pub1: " << pub1.size();
    xd(pub1);
  }
}

static std::string decipher(const std::string& data, const std::string& cipher,
                            const std::string& kdfname,
                            const std::string& kdfopts, const char* key) {
  // TODO
  THROW("Unhandled key encryption");
  return data;
}

static void handle_privkey(const std::string& data) {
  const void* d = data.data();
  ssize_t off = 0;
  uint32_t len, c1, c2;
  GETLEN(c1);
  GETLEN(c2);
  if (c1 != c2)
    THROW("Cannot extract data from openssh keydata: privkey checksum failed");
  GETLEN(len);
  CHECK_OFF(" - keytype");
  std::string keytype{ data.data() + off, len };
  off += len;
  BOOST_LOG_TRIVIAL(debug) << " - keytype: " << keytype;
  if (keytype == "ssh-rsa") {
    GETLEN(len);
    CHECK_OFF(" - rsa_n");
    std::string rsa_n{ data.data() + off, len };
    off += len;
    BOOST_LOG_TRIVIAL(debug) << " - rsa_n: " << rsa_n.size();
    xd(rsa_n);
    GETLEN(len);
    CHECK_OFF(" - rsa_e");
    std::string rsa_e{ data.data() + off, len };
    off += len;
    BOOST_LOG_TRIVIAL(debug) << " - rsa_e: " << rsa_e.size();
    xd(rsa_e);
    GETLEN(len);
    CHECK_OFF(" - rsa_d");
    std::string rsa_d{ data.data() + off, len };
    off += len;
    BOOST_LOG_TRIVIAL(debug) << " - rsa_d: " << rsa_d.size();
    xd(rsa_d);
    GETLEN(len);
    CHECK_OFF(" - rsa_iqmp");
    std::string rsa_iqmp{ data.data() + off, len };
    off += len;
    BOOST_LOG_TRIVIAL(debug) << " - rsa_iqmp: " << rsa_iqmp.size();
    xd(rsa_iqmp);
    GETLEN(len);
    CHECK_OFF(" - rsa_p");
    std::string rsa_p{ data.data() + off, len };
    off += len;
    BOOST_LOG_TRIVIAL(debug) << " - rsa_p: " << rsa_p.size();
    xd(rsa_p);
    GETLEN(len);
    CHECK_OFF(" - rsa_q");
    std::string rsa_q{ data.data() + off, len };
    off += len;
    BOOST_LOG_TRIVIAL(debug) << " - rsa_q: " << rsa_q.size();
    xd(rsa_q);
    GETLEN(len);
    CHECK_OFF(" - comment");
    std::string comment{ data.data() + off, len };
    off += len;
    BOOST_LOG_TRIVIAL(debug) << " - comment: " << comment;
    std::string padding{ data.data() + off, data.size() - off };
    BOOST_LOG_TRIVIAL(debug) << padding.size() << " bytes of padding...";
    xd(padding);
    return;
  }
  THROW("Unhandled key type");
}
