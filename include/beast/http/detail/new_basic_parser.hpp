//
// Copyright (c) 2013-2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BEAST_HTTP_DETAIL_NEW_BASIC_PARSER_HPP
#define BEAST_HTTP_DETAIL_NEW_BASIC_PARSER_HPP

#include <boost/algorithm/searching/boyer_moore.hpp>
#include <boost/utility/string_ref.hpp>
#include <boost/version.hpp>
#include <cstddef>
#include <utility>

namespace beast {
namespace http {
namespace detail {

class new_basic_parser_base
{
protected:
    static
    bool
    is_pathchar(char c)
    {
        // VFALCO This looks the same as the one below...

        // TEXT = <any OCTET except CTLs, and excluding LWS>
        static bool constexpr tab[256] = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //   0
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //  16
            0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //  32
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //  48
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //  64
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //  80
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //  96
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, // 112
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 128
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 144
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 160
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 176
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 192
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 208
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 224
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1  // 240
        };
        return tab[static_cast<unsigned char>(c)];
    }

    static
    bool
    is_value_char(char c)
    {
        // any OCTET except CTLs and LWS
        static bool constexpr tab[256] = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //   0
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //  16
            0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //  32
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //  48
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //  64
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //  80
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //  96
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, // 112
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 128
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 144
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 160
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 176
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 192
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 208
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 224
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1  // 240
        };
        return tab[static_cast<unsigned char>(c)];
    }

    static
    inline
    bool
    is_text(char c)
    {
        // TEXT = <any OCTET except CTLs, but including LWS>
        static bool constexpr tab[256] = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, //   0
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //  16
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //  32
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //  48
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //  64
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //  80
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //  96
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, // 112
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 128
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 144
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 160
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 176
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 192
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 208
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 224
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1  // 240
        };
        return tab[static_cast<unsigned char>(c)];
    }

    static
    inline
    bool
    unhex(unsigned char& d, char c)
    {
        static signed char constexpr tab[256] = {
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, //   0
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, //  16
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, //  32
             0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1, //  48
            -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1, //  64
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, //  80
            -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1, //  96
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1  // 112

            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1  // 128
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1  // 144
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1  // 160
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1  // 176
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1  // 192
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1  // 208
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1  // 224
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1  // 240
        };
        d = static_cast<unsigned char>(
            tab[static_cast<unsigned char>(c)]);
        return d != static_cast<unsigned char>(-1);
    }

    static
    bool
    is_digit(char c)
    {
        return static_cast<unsigned char>(c-'0') < 10;
    }

    static
    bool
    is_print(char c)
    {
        return static_cast<unsigned char>(c-33) < 94;
    }

    static
    boost::string_ref
    make_string(char const* first, char const* last)
    {
        return {first, static_cast<
            std::size_t>(last - first)};
    }

    template<class Iter, class Unsigned>
    static
    bool
    parse_dec(Iter it, Iter last, Unsigned& v)
    {
        if(! is_digit(*it))
            return false;
        v = *it - '0';
        for(;;)
        {
            if(! is_digit(*++it))
                break;
            auto const d = *it - '0';
            if(v > ((std::numeric_limits<
                    Unsigned>::max)() - 10) / 10)
                return false;
            v = 10 * v + d;
        }
        return true;
    }

    template<class Iter, class Unsigned>
    bool
    parse_hex(Iter& it, Unsigned& v)
    {
        unsigned char d;
        if(! unhex(d, *it))
            return false;
        v = d;
        for(;;)
        {
            if(! unhex(d, *++it))
                break;
            auto const v0 = v;
            v = 16 * v + d;
            if(v <= v0)
                return false;
        }
        return true;
    }

    static
    bool
    parse_crlf(char const*& it)
    {
        if(*it != '\r')
            return false;
        if(*++it != '\n')
            return false;
        ++it;
        return true;
    }

    template<class F>
    static
    boost::string_ref
    parse_as(char const*& it, F const& f)
    {
        auto const first = it;
        while(f(*it))
            ++it;
        if(*it != ' ')
            return {};
        return {first, static_cast<
            boost::string_ref::size_type>(
                it - first)};
    }

    static
    int
    parse_version(char const*& it)
    {
        if(*it != 'H')
            return -1;
        if(*++it != 'T')
            return -1;
        if(*++it != 'T')
            return -1;
        if(*++it != 'P')
            return -1;
        if(*++it != '/')
            return -1;
        if(! is_digit(*++it))
            return -1;
        int v = 10 * (*it - '0');
        if(*++it != '.')
            return -1;
        if(! is_digit(*++it))
            return -1;
        v += *it++ - '0';
        return v;
    }

    static
    int
    parse_status(char const*& it)
    {
        int v;
        if(! is_digit(*it))
            return -1;
        v = 100 * (*it - '0');
        if(! is_digit(*++it))
            return -1;
        v += 10 * (*it - '0');
        if(! is_digit(*++it))
            return -1;
        v += (*it++ - '0');
        return v;
    }
    
    static
    boost::string_ref
    parse_reason(char const*& it)
    {
        auto const first = it;
        while(*it != '\r')
        {
            if(! is_text(*it))
                return {};
            ++it;
        }
        return {first, static_cast<
            std::size_t>(it - first)};
    }

    // VFALCO This can be optimized with SIMD if available
    template<class Iter>
    static
    std::pair<Iter, Iter>
    find_crlf(Iter first, Iter last)
    {
        static char const pat[] = "\r\n";
        static boost::algorithm::boyer_moore<
            char const*> const bm{pat, pat+2};
    #if BOOST_VERSION >= 106200
        return bm(first, last);
    #else
        auto const it = bm(first, last);
        return {it, it+2};
    #endif
    }

    // VFALCO This can be optimized with SIMD if available
    template<class Iter>
    static
    std::pair<Iter, Iter>
    find_2x_crlf(Iter first, Iter last)
    {
        static char const pat[] = "\r\n\r\n";
        static boost::algorithm::boyer_moore<
            char const*> const bm{pat, pat+4};
    #if BOOST_VERSION >= 106200
        return bm(first, last);
    #else
        auto const it = bm(first, last);
        return {it, it+4};
    #endif
    }
};

} // detail
} // http
} // beast

#endif
