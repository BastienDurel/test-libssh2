#if !defined LIBLAUNCH_UTILS_HPP_INCLUDED
#define LIBLAUNCH_UTILS_HPP_INCLUDED 1

#include <ostream>
#include <string>
#if defined HAVE_UNISTD
#include <unistd.h>
#endif
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>

struct base64dump {
  std::string s;
  const std::string& ref;
  explicit base64dump(const std::string& a) : ref(a) {}
  explicit base64dump(const char* a, size_t len) : s(a, len), ref(s) {}
};
std::ostream& operator<< (std::ostream& stream, const base64dump& v);

class unlinkable {
  std::string filename;
public:
  unlinkable(const std::string &fname) : filename(fname) {}
  unlinkable(const unlinkable&) = delete;
  unlinkable(unlinkable&& from) { std::swap(filename, from.filename); }
  ~unlinkable() {
    if (!filename.empty())
#if defined _MSC_VER
      _unlink
#else
        unlink
#endif
        (filename.c_str());
  }
  operator const std::string&() const { return filename; }
  const std::string& fn() const { return filename; }
};

template <typename T> void my_delete(T* a) { delete a; }
template <typename T, typename R = void, R Deleter(T*) = my_delete<T> >
struct auto_del {
  T* m;
  auto_del(T* a) : m(a) {}
  ~auto_del() { if (m) Deleter(m); }
  // return 0 as integral value
  template <typename U=R, typename std::enable_if<std::is_integral<U>::value, R>::type = 0>
  U force() { T* i = m; m = nullptr; if (i) return Deleter(m); return 0; }
  // specialization for void
  template <typename U=R, typename std::enable_if<std::is_same<U, void>::value, void>::type = 0>
  U force() { T* i = m; m = nullptr; if (i) Deleter(m); }
};

template <typename T>
struct autofn {
  T fn;
  bool done = false;
  autofn(const T& f) : fn(f) {}
  autofn(const autofn&) = delete;
  autofn(autofn&&) = delete;
  ~autofn() { if (!done) fn(); }
  void force() { if (!done) fn(); done = true; }
};

struct sview {
  const std::string& s;
  const size_t len;
  sview(const std::string& s_, size_t len_ = 72) : s(s_), len(len_) {}
};
static std::ostream& operator<< (std::ostream& stream, const sview& v) {
  return stream << v.s.substr(0, std::min(v.len, v.s.size()));
}

struct auto_close_sock {
  boost::asio::ip::tcp::socket& s;
  auto_close_sock(boost::asio::ip::tcp::socket& _s) : s(_s) {}
  ~auto_close_sock() { s.close(); }
};

#endif
