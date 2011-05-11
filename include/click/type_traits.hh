#ifndef CLICK_TYPE_TRAITS_HH
#define CLICK_TYPE_TRAITS_HH

template<typename T, T val>
struct integral_constant {
    typedef integral_constant<T, val> type;
    typedef T value_type;
    static constexpr T value = val;
};
typedef integral_constant<bool, true> true_type;
typedef integral_constant<bool, false> false_type;

template<typename T> struct has_trivial_copy : public false_type {};
template<> struct has_trivial_copy<unsigned char> : public true_type {};
template<> struct has_trivial_copy<signed char> : public true_type {};
template<> struct has_trivial_copy<char> : public true_type {};
template<> struct has_trivial_copy<unsigned short> : public true_type {};
template<> struct has_trivial_copy<short> : public true_type {};
template<> struct has_trivial_copy<unsigned> : public true_type {};
template<> struct has_trivial_copy<int> : public true_type {};
template<> struct has_trivial_copy<unsigned long> : public true_type {};
template<> struct has_trivial_copy<long> : public true_type {};
#if HAVE_LONG_LONG
template<> struct has_trivial_copy<unsigned long long> : public true_type {};
template<> struct has_trivial_copy<long long> : public true_type {};
#endif
template<typename T> struct has_trivial_copy<T *> : public true_type {};


#if HAVE_INT64_TYPES && (!HAVE_LONG_LONG || SIZEOF_LONG_LONG < 8)
typedef int64_t click_int_large_t;
typedef uint64_t click_uint_large_t;
# define SIZEOF_CLICK_INT_LARGE_T 8
#elif HAVE_LONG_LONG
typedef long long click_int_large_t;
typedef unsigned long long click_uint_large_t;
# define SIZEOF_CLICK_INT_LARGE_T SIZEOF_LONG_LONG
#else
typedef long click_int_large_t;
typedef unsigned long click_uint_large_t;
# define SIZEOF_CLICK_INT_LARGE_T SIZEOF_LONG
#endif


/** @class integer_traits
  @brief Numeric traits template.

  The integer_traits template defines constants and type definitions related
  to integers.  Where T is an integer, integer_traits<T> defines:

  <dl>
  <dt>const T const_min</dt>
  <dd>The minimum value defined for the type.</dd>
  <dt>const T const_max</dt>
  <dd>The maximum value available for the type.</dd>
  <dt>const bool is_numeric</dt>
  <dd>True.</dd>
  <dt>const bool is_integer</dt>
  <dd>True.</dd>
  <dt>const bool is_signed</dt>
  <dd>True iff the type is signed.</dd>
  <dt>signed_type (typedef)</dt>
  <dd>Signed version of the type.</dd>
  <dt>unsigned_type (typedef)</dt>
  <dd>Unsigned version of the type.</dd>
  </dl>

  If T is <em>not</em> an integer, integer_traits<T> defines:

  <dl>
  <dt>constexpr bool is_numeric</dt>
  <dd>False.</dd>
  <dt>constexpr bool is_integer</dt>
  <dd>False.</dd>
  </dl> */
template<typename T>
struct integer_traits {
    static constexpr bool is_numeric = false;
    static constexpr bool is_integer = false;
};

template<>
struct integer_traits<unsigned char> {
    static constexpr bool is_numeric = true;
    static constexpr bool is_integer = true;
    static constexpr unsigned char const_min = 0;
    static constexpr unsigned char const_max = ~const_min;
    static constexpr bool is_signed = false;
    typedef signed char signed_type;
    typedef unsigned char unsigned_type;
    typedef unsigned char type;
    static bool negative(type) { return false; }
};

template<>
struct integer_traits<signed char> {
    static constexpr bool is_numeric = true;
    static constexpr bool is_integer = true;
    static constexpr signed char const_min = -128;
    static constexpr signed char const_max = 127;
    static constexpr bool is_signed = true;
    typedef signed char signed_type;
    typedef unsigned char unsigned_type;
    typedef signed char type;
    static bool negative(type x) { return x < 0; }
};

#if __CHAR_UNSIGNED__
template<>
struct integer_traits<char> : public integer_traits<unsigned char> {
    static constexpr char const_min = 0;
    static constexpr char const_max = ~const_min;
    typedef char type;
    static bool negative(type) { return false; }
};
#else
template<>
struct integer_traits<char> : public integer_traits<signed char> {
    static constexpr char const_min = -128;
    static constexpr char const_max = 127;
    typedef char type;
    static bool negative(type x) { return x < 0; }
};
#endif

template<>
struct integer_traits<unsigned short> {
    static constexpr bool is_numeric = true;
    static constexpr bool is_integer = true;
    static constexpr unsigned short const_min = 0;
    static constexpr unsigned short const_max = ~const_min;
    static constexpr bool is_signed = false;
    typedef short signed_type;
    typedef unsigned short unsigned_type;
    typedef unsigned short type;
    static bool negative(type) { return false; }
};

template<>
struct integer_traits<short> {
    static constexpr bool is_numeric = true;
    static constexpr bool is_integer = true;
    static constexpr short const_min = -32768;
    static constexpr short const_max = 32767;
    static constexpr bool is_signed = true;
    typedef short signed_type;
    typedef unsigned short unsigned_type;
    typedef short type;
    static bool negative(type x) { return x < 0; }
};

template<>
struct integer_traits<unsigned int> {
    static constexpr bool is_numeric = true;
    static constexpr bool is_integer = true;
    static constexpr unsigned int const_min = 0;
    static constexpr unsigned int const_max = ~const_min;
    static constexpr bool is_signed = false;
    typedef int signed_type;
    typedef unsigned int unsigned_type;
    typedef unsigned int type;
    static bool negative(type) { return false; }
};

template<>
struct integer_traits<int> {
    static constexpr bool is_numeric = true;
    static constexpr bool is_integer = true;
    static constexpr int const_min = 1 << (8*SIZEOF_INT - 1);
    static constexpr int const_max = (unsigned) const_min - 1;
    static constexpr bool is_signed = true;
    typedef int signed_type;
    typedef unsigned int unsigned_type;
    typedef int type;
    static bool negative(type x) { return x < 0; }
};

template<>
struct integer_traits<unsigned long> {
    static constexpr bool is_numeric = true;
    static constexpr bool is_integer = true;
    static constexpr unsigned long const_min = 0;
    static constexpr unsigned long const_max = ~const_min;
    static constexpr bool is_signed = false;
    typedef long signed_type;
    typedef unsigned long unsigned_type;
    typedef unsigned long type;
    static bool negative(type) { return false; }
};

template<>
struct integer_traits<long> {
    static constexpr bool is_numeric = true;
    static constexpr bool is_integer = true;
    static constexpr long const_min = (long) 1 << (8*SIZEOF_LONG - 1);
    static constexpr long const_max = (unsigned long) const_min - 1;
    static constexpr bool is_signed = true;
    typedef long signed_type;
    typedef unsigned long unsigned_type;
    typedef long type;
    static bool negative(type x) { return x < 0; }
};

#if HAVE_LONG_LONG
template<>
struct integer_traits<unsigned long long> {
    static constexpr bool is_numeric = true;
    static constexpr bool is_integer = true;
    static constexpr unsigned long long const_min = 0;
    static constexpr unsigned long long const_max = ~const_min;
    static constexpr bool is_signed = false;
    typedef long long signed_type;
    typedef unsigned long long unsigned_type;
    typedef unsigned long long type;
    static bool negative(type) { return false; }
};

template<>
struct integer_traits<long long> {
    static constexpr bool is_numeric = true;
    static constexpr bool is_integer = true;
    static constexpr long long const_min = (long long) 1 << (8*SIZEOF_LONG_LONG - 1);
    static constexpr long long const_max = (unsigned long long) const_min - 1;
    static constexpr bool is_signed = true;
    typedef long long signed_type;
    typedef unsigned long long unsigned_type;
    typedef long long type;
    static bool negative(type x) { return x < 0; }
};
#endif

#if HAVE_INT64_TYPES && !HAVE_INT64_IS_LONG && !HAVE_INT64_IS_LONG_LONG
template<>
struct integer_traits<uint64_t> {
    static constexpr bool is_numeric = true;
    static constexpr bool is_integer = true;
    static constexpr uint64_t const_min = 0;
    static constexpr uint64_t const_max = ~const_min;
    static constexpr bool is_signed = false;
    typedef int64_t signed_type;
    typedef uint64_t unsigned_type;
    typedef uint64_t type;
    static bool negative(type) { return false; }
};

template<>
struct integer_traits<int64_t> {
    static constexpr bool is_numeric = true;
    static constexpr bool is_integer = true;
    static constexpr int64_t const_min = (int64_t) 1 << 63;
    static constexpr int64_t const_max = (uint64_t) const_min - 1;
    static constexpr bool is_signed = true;
    typedef int64_t signed_type;
    typedef uint64_t unsigned_type;
    typedef int64_t type;
    static bool negative(type x) { return x < 0; }
};
#endif


/** @class make_signed
  @brief Signed integer type transformation.

  Given an integer type T, the type make_signed<T>::type is the signed version
  of T.

  @sa integer_traits */
template<typename T>
struct make_signed {
    typedef typename integer_traits<T>::signed_type type;
};

/** @class make_unsigned
  @brief Unsigned integer type transformation.

  Given an integer type T, the type make_unsigned<T>::type is the unsigned
  version of T.

  @sa integer_traits */
template<typename T>
struct make_unsigned {
    typedef typename integer_traits<T>::unsigned_type type;
};


/** @cond never */
template<typename T, typename Thalf>
struct make_fast_half_integer {
    typedef T type;
    typedef Thalf half_type;
    static constexpr int half_bits = int(sizeof(type) * 4);
    static constexpr type half_value = type(1) << half_bits;
    static half_type low(type x) {
	return x & (half_value - 1);
    }
    static half_type high(type x) {
	return x >> (sizeof(type) * 4);
    }
};

/** @class fast_half_integer
  @brief Type transformation for big integers. */
template<typename T> struct fast_half_integer : public make_fast_half_integer<T, T> {};

#if SIZEOF_LONG >= 8 && SIZEOF_LONG <= 2 * SIZEOF_INT
template<> struct fast_half_integer<unsigned long> : public make_fast_half_integer<unsigned long, unsigned int> {};
#endif

#if HAVE_LONG_LONG && SIZEOF_LONG_LONG <= 2 * SIZEOF_INT
template<> struct fast_half_integer<unsigned long long> : public make_fast_half_integer<unsigned long long, unsigned int> {};
#endif

#if HAVE_INT64_TYPES && !HAVE_INT64_IS_LONG_LONG && !HAVE_INT64_IS_LONG && SIZEOF_INT >= 4
template <> struct fast_half_integer<uint64_t> : public make_fast_half_integer<uint64_t, unsigned int> {};
#endif


/** @class conditional
  @brief Conditional type transformation.

  If B is true, then conditional<B, T, F>::type is equivalent to T.
  Otherwise, it is equivalent to F. */
template<bool B, typename T, typename F>
struct conditional {
};

template<typename T, typename F>
struct conditional<true, T, F> {
    typedef T type;
};

template<typename T, typename F>
struct conditional<false, T, F> {
    typedef F type;
};


template<int n, typename Limb, typename V>
struct extract_integer_template {
    static void extract(const Limb *x, V &value) {
	extract_integer_template<n - 1, Limb, V>::extract(x + 1, value);
	value = (value << (sizeof(Limb) * 8)) | *x;
    }
};

template<typename Limb, typename V>
struct extract_integer_template<1, Limb, V> {
    static void extract(const Limb *x, V &value) {
	value = x[0];
    }
};

template<typename Limb, typename V>
inline void extract_integer(const Limb *x, V &value) {
    extract_integer_template<
	int((sizeof(V) + sizeof(Limb) - 1) / sizeof(Limb)), Limb, V
	>::extract(x, value);
}

#endif