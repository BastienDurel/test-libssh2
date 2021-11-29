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

#define GETLEN(l) do { const uint32_t *len_ = reinterpret_cast<const uint32_t*>((unsigned char*)(d) + off); l = ntohl(*len_); off += sizeof(uint32_t); } while (0)
#define CHECK_OFF(x)  BOOST_LOG_TRIVIAL(debug) << x " len: " << len; if ((off + len) > data.size()) THROW("Cannot extract data from openssh keydata: invalid length")

std::string openssh2pem(const std::string& keydata) {
  BOOST_LOG_TRIVIAL(debug) << "Trying to convert " << sview(keydata);
  std::istringstream i{ keydata };
  char buf[76];
  bool in_header = false;
  std::string data;
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
    data.append(decode(buf));
    BOOST_LOG_TRIVIAL(trace) << "buf: " << buf;
  }
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
  BOOST_LOG_TRIVIAL(debug) << "pubkey: " << pubkey.size() << " bytes";
  GETLEN(len);
  CHECK_OFF("privkey");
  std::string privkey{ data.data() + off, len };
  off += len;
  BOOST_LOG_TRIVIAL(debug) << "privkey: " << privkey.size() << " bytes";
  return keydata;
}

static void handle_pubkey(const std::string& data) {
  const void* d = data.data();
  ssize_t off = 0;
  uint32_t len;
  GETLEN(len);
  CHECK_OFF("keytype");
  std::string keytype{ data.data() + off, len };
  off += len;
  BOOST_LOG_TRIVIAL(debug) << " - keytype: " << keytype;
}
