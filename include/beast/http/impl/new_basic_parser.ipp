//
// Copyright (c) 2013-2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BEAST_HTTP_IMPL_NEW_BASIC_PARSER_IPP
#define BEAST_HTTP_IMPL_NEW_BASIC_PARSER_IPP

#include <beast/core/buffer_concepts.hpp>
#include <beast/core/detail/ci_char_traits.hpp>
#include <beast/core/detail/clamp.hpp>
#include <beast/core/detail/type_traits.hpp>
#include <beast/http/rfc7230.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/assert.hpp>

namespace beast {
namespace http {

template<bool isRequest, class Derived>
new_basic_parser<isRequest, Derived>::
~new_basic_parser()
{
    if(buf_)
        delete[] buf_;
}

template<bool isRequest, class Derived>
template<class ConstBufferSequence>
std::size_t
new_basic_parser<isRequest, Derived>::
write(ConstBufferSequence const& buffers,
    error_code& ec)
{
    static_assert(is_ConstBufferSequence<
        ConstBufferSequence>::value,
            "ConstBufferSequence not met");
    if(! (f_ & flagHeader))
    {
        auto const s =
            maybe_flatten(buffers);
        return parse_header(
            s.data(), s.size(), ec);
    }
    if(f_ & flagChunked)
    {
        auto const s =
            maybe_flatten(buffers);
        return parse_chunked(
            s.data(), s.size(), ec);
    }
    return 0;
}

template<bool isRequest, class Derived>
void
new_basic_parser<isRequest, Derived>::
write_eof(error_code& ec)
{
    if(f_ & (flagContentLength | flagChunked))
    {
        if(! (f_ & flagDone))
        {
            ec = error::short_read;
            return;
        }
    }
    else
    {
        f_ |= flagDone;
    }
}

template<bool isRequest, class Derived>
template<class Reader, class DynamicBuffer>
void
new_basic_parser<isRequest, Derived>::
write_body(Reader& r,
    DynamicBuffer& dynabuf, error_code& ec)
{
    using boost::asio::buffer_copy;
    auto const n = beast::detail::clamp(
        len_, dynabuf.size());
    auto const b = r.prepare(n, ec);
    if(ec)
        return;
    auto const len = buffer_copy(
        b, dynabuf.data(), n);
    r.commit(len, ec);
    if(ec)
        return;
    dynabuf.consume(len);
    if(f_ & flagContentLength)
    {
        len_ -= len;
        if(len_ == 0)
            f_ |= flagDone;
    }
    else if(f_ & flagChunked)
    {
        len_ -= len;
    }
}

template<bool isRequest, class Derived>
template<class ConstBufferSequence>
boost::string_ref
new_basic_parser<isRequest, Derived>::
maybe_flatten(
    ConstBufferSequence const& buffers)
{
    using boost::asio::buffer;
    using boost::asio::buffer_cast;
    using boost::asio::buffer_copy;
    using boost::asio::buffer_size;

    auto const it = buffers.begin();
    auto const last = buffers.end();
    if(it == last)
        return {nullptr, 0};
    if(std::next(it) == last)
    {
        // single buffer
        auto const b = *it;
        return {buffer_cast<char const*>(b),
            buffer_size(b)};
    }
    auto const len = buffer_size(buffers);
    if(len > buf_len_)
    {
        // reallocate
        if(buf_)
            delete[] buf_;
        buf_ = new char[len];
        buf_len_ = len;
    }
    // flatten
    buffer_copy(
        buffer(buf_, buf_len_), buffers);
    return {buf_, buf_len_};
}

template<bool isRequest, class Derived>
void
new_basic_parser<isRequest, Derived>::
parse_startline(char const*& it,
    error_code& ec, std::true_type)
{
/*
    request-line   = method SP request-target SP HTTP-version CRLF
    method         = token
*/
    auto const method =
        parse_as(it, &detail::is_tchar);
    if(method.empty())
    {
        ec = error::bad_method;
        return;
    }
    ++it;

    auto const path =
        parse_as(it, &is_pathchar);
    if(path.empty())
    {
        ec = error::bad_path;
        return;
    }
    ++it;

    auto const version = parse_version(it);
    if(version < 0 || ! parse_crlf(it))
    {
        ec = error::bad_version;
        return;
    }

    impl().on_request(
        method, path, version, ec);
    if(ec)
        return;
}

template<bool isRequest, class Derived>
void
new_basic_parser<isRequest, Derived>::
parse_startline(char const*& it,
    error_code& ec, std::false_type)
{
/*
     status-line    = HTTP-version SP status-code SP reason-phrase CRLF
     status-code    = 3*DIGIT
     reason-phrase  = *( HTAB / SP / VCHAR / obs-text )
*/
    auto const version = parse_version(it);
    if(version < 0 || *it != ' ')
    {
        ec = error::bad_version;
        return;
    }
    ++it;

    auto const status = parse_status(it);
    if(status < 0 || *it != ' ')
    {
        ec = error::bad_status;
        return;
    }
    ++it;

    auto const reason = parse_reason(it);
    if(reason.empty() || ! parse_crlf(it))
    {
        ec = error::bad_reason;
        return;
    }

    impl().on_response(
        status, reason, version, ec);
    if(ec)
        return;
}

template<bool isRequest, class Derived>
void
new_basic_parser<isRequest, Derived>::
parse_fields(char const*& it, error_code& ec)
{
/*  header-field   = field-name ":" OWS field-value OWS

    field-name     = token
    field-value    = *( field-content / obs-fold )
    field-content  = field-vchar [ 1*( SP / HTAB ) field-vchar ]
    field-vchar    = VCHAR / obs-text

    obs-fold       = CRLF 1*( SP / HTAB )
                   ; obsolete line folding
                   ; see Section 3.2.4
*/
    for(;;)
    {
        if(*it == '\r')
        {
            if(*++it != '\n')
            {
                ec = error::bad_field;
                return;
            }
            ++it;
            return;
        }
        auto first = it;
        boost::string_ref name;
        for(;;)
        {
            if(*it == ':')
            {
                name = make_string(
                    first, it++);
                break;
            }
            if(! detail::to_field_char(*it))
            {
                ec = error::bad_field;
                return;
            }
            ++it;
        }
        while(*it == ' ' || *it == '\t')
            ++it;
        first = it;
        auto last = it;
        for(;;)
        {
            if(*it == '\r')
            {
                if(*++it != '\n')
                {
                    ec = error::bad_field;
                    return;
                }
                ++it;
                if(*it != ' ' && *it != '\t')
                    break;
                // we have obs-fold
            }
            if(is_value_char(*it))
            {
                last = ++it;
            }
            else if(*it == ' ' || *it == '\t')
            {
                ++it;
            }
            else
            {
                ec = error::bad_value;
                return;
            }
        }
        auto const value =
            make_string(first, last);
        do_field(name, value, ec);
        if(ec)
            return;
        impl().on_field(name,
            make_string(first, last), ec);
        if(ec)
            return;
    }
}

template<bool isRequest, class Derived>
void
new_basic_parser<isRequest, Derived>::
do_field(
    boost::string_ref const& name,
        boost::string_ref const& value,
            error_code& ec)
{
    // Content-Length
    if(beast::detail::ci_equal(name, "Content-Length"))
    {
        if(f_ & flagChunked)
        {
            ec = error::bad_content_length;
            return;
        }

        if(f_ & flagContentLength)
        {
            ec = error::bad_content_length;
            return;
        }

        std::uint64_t v;
        if(! parse_dec(value.begin(), value.end(), v))
        {
            ec = error::bad_content_length;
            return;
        }
        len_ = v;
        f_ |= flagContentLength;
        return;
    }

    // Connection
    if(beast::detail::ci_equal(name, "Connection"))
    {
        ec = {};
        return;
    }

    // Transfer-Encoding
    if(beast::detail::ci_equal(name, "Transfer-Encoding"))
    {
        if(f_ & flagContentLength)
        {
            ec = error::bad_transfer_encoding;
            return;
        }

        if(f_ & flagChunked)
        {
            ec = error::bad_transfer_encoding;
            return;
        }

        auto const v = token_list{value};
        auto const it = std::find_if(v.begin(), v.end(),
            [&](typename token_list::value_type const& s)
            {
                return beast::detail::ci_equal(s, "chunked");
            });
        if(std::next(it) != v.end())
        {
            ec = error::bad_transfer_encoding;
            return;
        }
        f_ |= flagChunked;
        return;
    }

    // Upgrade (TODO)
    if(beast::detail::ci_equal(name, "Upgrade"))
    {
        ec = {};
        return;
    }

    // Proxy-Connection (TODO)
    if(beast::detail::ci_equal(name, "Proxy-Connection"))
    {
        ec = {};
        return;
    }
}

template<bool isRequest, class Derived>
std::size_t
new_basic_parser<isRequest, Derived>::
parse_header(char const* p,
    std::size_t n, error_code& ec)
{
    if(n < 4)
    {
        ec = error::need_more;
        return 0;
    }
    auto const term =
        find_2x_crlf(p + skip_, p + n);
    if(term.first == term.second)
    {
        skip_ = n - 3;
        ec = error::need_more;
        return 0;
    }

    skip_ = 0;
    n = term.second - p;
    parse_startline(p, ec,
        std::integral_constant<
            bool, isRequest>{});
    if(ec)
        return 0;
    parse_fields(p, ec);
    if(ec)
        return 0;
    BOOST_ASSERT(p == term.second);
    impl().on_header(ec);
    if(ec)
        return 0;
    f_ |= flagHeader;
    return n;
}

template<bool isRequest, class Derived>
std::size_t
new_basic_parser<isRequest, Derived>::
parse_chunked(char const* p,
    std::size_t n, error_code& ec)
{
/*
    chunked-body   = *chunk
                        last-chunk
                        trailer-part
                        CRLF

    chunk          = chunk-size [ chunk-ext ] CRLF
                        chunk-data CRLF
    last-chunk     = 1*("0") [ chunk-ext ] CRLF
    trailer-part   = *( header-field CRLF )

    chunk-size     = 1*HEXDIG
    chunk-data     = 1*OCTET ; a sequence of chunk-size octets
    chunk-ext      = *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
    chunk-ext-name = token
    chunk-ext-val  = token / quoted-string
*/

    auto const first = p;
    auto const last = p + n;

    if(f_ & flagExpectCRLF)
    {
        // We treat the final CRLF in a chunk as part of the
        // next chunk, so it can be parsed in just one call.
        if(n < 2)
        {
            ec = error::need_more;
            return 0;
        }
        if(! parse_crlf(p))
        {
            ec = error::bad_chunk;
            return 0;
        }
        n -= 2;
    }

    std::pair<char const*, char const*> term;

    if(! (f_ & flagFinalChunk))
    {
        if(n < 2)
        {
            ec = error::need_more;
            return 0;
        }
        term = find_crlf(p + skip_, last);
        if(term.first == term.second)
        {
            skip_ = n - 1;
            ec = error::need_more;
            return 0;
        }
        std::uint64_t v;
        if(! parse_hex(p, v))
        {
            ec = error::bad_chunk;
            return 0;
        }
        if(v != 0)
        {
            if(*p == ';')
            {
                // VFALCO We need to parse the chunk
                // extension to validate it here.
                impl().on_chunk(v,
                    make_string(
                        p, term.first), ec);
                if(ec)
                    return 0;
            }
            else if(p != term.first)
            {
                ec = error::bad_chunk;
                return 0;
            }
            p = term.second;
            len_ = v;
            skip_ = 0;
            f_ |= flagExpectCRLF;
            return p - first;
        }

        // This is the offset from the buffer
        // to the beginning of the first '\r\n'
        x_ = term.first - first;
        skip_ = x_;
    }

    term = find_2x_crlf(first + skip_, last);
    if(term.first == term.second)
    {
        if(n > 3)
            skip_ = (last - first) - 3;
        ec = error::need_more;
        return 0;
    }
        
    if(f_ & flagFinalChunk)
    {
        // We are parsing the value again
        // to advance p to the right place.
        std::uint64_t v;
        auto const result = parse_hex(p, v);
        BOOST_ASSERT(result && v == 0);
        beast::detail::ignore_unused(result);
        beast::detail::ignore_unused(v);
    }
    else
    {
        f_ |= flagFinalChunk;
    }

    if(*p == ';')
    {
        impl().on_chunk(0,
            make_string(
                p, first + x_), ec);
        if(ec)
            return 0;
        p = first + x_;
    }
    if(! parse_crlf(p))
    {
        ec = error::bad_chunk;
        return 0;
    }
    parse_fields(p, ec);
    if(ec)
        return 0;
    BOOST_ASSERT(p == term.second);
    f_ |= flagDone;
    return p - first;
}

} // http
} // beast

#endif
