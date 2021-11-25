#include <boost/log/trivial.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include "utils.hpp"
#include "test.hpp"
#if defined HAVE_UNISTD
#include <unistd.h>
#endif

boost::filesystem::path home() {
#if defined _WIN32 || defined _WIN64
  WCHAR path[MAX_PATH + 1] = { 0 };
  if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, path))) {
    return boost::filesystem::path{ path };
  }
#endif
#if defined _MSC_VER
  // MSVC doesn't like getenv(3)
# pragma warning(push)
# pragma warning(disable: 4996)
#endif
  char const* home = getenv("HOME");
  if (home || ((home = getenv("USERPROFILE")))) {
    return boost::filesystem::path{ home };
  }
  else {
    char const *hdrive = getenv("HOMEDRIVE"),
      *hpath = getenv("HOMEPATH");
    if (hdrive && hpath)
      return boost::filesystem::path{ std::string(hdrive) + hpath };
  }
#if defined _MSC_VER
# pragma warning(pop)
#endif
  BOOST_LOG_TRIVIAL(info) << "Cannot find home directory";
  return boost::filesystem::path{ "." };
}

std::ostream& operator<< (std::ostream& stream, const base64dump& v) {
  using namespace boost::archive::iterators;
  using It = base64_from_binary<transform_width
                                <std::string::const_iterator, 6, 8>>;
  auto tmp = std::string(It(std::begin(v.ref)), It(std::end(v.ref)));
  return stream << tmp.append((3 - v.ref.size() % 3) % 3, '=');
}
