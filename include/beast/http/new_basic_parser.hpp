//
// Copyright (c) 2013-2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BEAST_HTTP_NEW_BASIC_PARSER_HPP
#define BEAST_HTTP_NEW_BASIC_PARSER_HPP

#include <beast/core/error.hpp>
#include <boost/optional.hpp>
#include <boost/utility/string_ref.hpp>
#include <beast/http/detail/new_basic_parser.hpp>

namespace beast {
namespace http {

enum class error
{
    /** More input is necessary to continue parsing.
    */
    need_more = 1,

    /// The method is invalid.
    bad_method,

    /// The request-target is invalid.
    bad_path,

    /// The HTTP-version is invalid.
    bad_version,

    /// The status-code is invalid.
    bad_status,

    /// The reason-phrase is invalid.
    bad_reason,

    /// The field name is invalid.
    bad_field,

    /// The field value is invalid.
    bad_value,

    /// The Content-Length is invalid.
    bad_content_length,

    /// The Transfer-Encoding is invalid.
    bad_transfer_encoding,

    /// The chunk syntax is invalid.
    bad_chunk,

    /// Unexpected end of message
    short_read
};

} // http
} // beast

namespace boost {
namespace system {
template<>
struct is_error_code_enum<beast::http::error>
{
    static bool const value = true;
};
} // system
} // boost

namespace beast {
namespace http {

namespace detail {

class http_error_category : public error_category
{
public:
    const char*
    name() const noexcept override
    {
        return "http";
    }

    std::string
    message(int ev) const override
    {
        switch(static_cast<error>(ev))
        {
        default:
        case error::need_more: return "more input needed";
        case error::bad_method: return "bad method";
        case error::bad_path: return "bad path";
        case error::bad_version: return "bad version";
        case error::bad_status: return "bad status";
        case error::bad_reason: return "bad reason";
        case error::bad_field: return "bad field";
        case error::bad_value: return "bad value";
        case error::bad_content_length: return "bad Content-Length";
        case error::bad_transfer_encoding: return "bad Transfer-Encoding";
        case error::bad_chunk: return "bad chunk";
        case error::short_read: return "unexpected end of message";
        }
    }

    error_condition
    default_error_condition(int ev) const noexcept override
    {
        return error_condition{ev, *this};
    }

    bool
    equivalent(int ev,
        error_condition const& condition
            ) const noexcept override
    {
        return condition.value() == ev &&
            &condition.category() == this;
    }

    bool
    equivalent(error_code const& error, int ev) const noexcept override
    {
        return error.value() == ev &&
            &error.category() == this;
    }
};

inline
error_category const&
get_http_error_category()
{
    static http_error_category const cat{};
    return cat;
}

} // detail

inline
error_code
make_error_code(error ev)
{
    return error_code{
        static_cast<std::underlying_type<error>::type>(ev),
            detail::get_http_error_category()};
}

//------------------------------------------------------------------------------

template<
    bool isRequest,
    class Derived>
class new_basic_parser
    : private detail::new_basic_parser_base
{
    static unsigned constexpr flagContentLength = 1;
    static unsigned constexpr flagChunked = 2;
    static unsigned constexpr flagUpgrade = 4;
    static unsigned constexpr flagHeader = 8;
    static unsigned constexpr flagDone = 16;
    static unsigned constexpr flagExpectCRLF = 32;
    static unsigned constexpr flagFinalChunk = 64;
    static unsigned constexpr flagSkipBody = 128;

    char* buf_ = nullptr;
    std::size_t buf_len_ = 0;

    std::uint64_t len_ =
        (std::numeric_limits<std::uint64_t>::max)();
    std::uint32_t skip_ = 0;    // search from here
    std::uint32_t x_;           // scratch variable
    std::uint8_t f_ = 0;        // flags

public:
    /// Destructor
    ~new_basic_parser();

    /// Returns `true` if a complete message has been received
    bool
    done() const
    {
        return (f_ & flagDone) != 0;
    }

    /// Returns true if we have already received a complete header
    bool
    have_header() const
    {
        return (f_ & flagHeader) != 0;
    }

    /** Returns `true` if the Transfer-Encoding specifies chunked

        @note The return value is undefined unless @ref have_header
        would return `true`
    */
    bool
    is_chunked() const
    {
        return (f_ & flagChunked) != 0;
    }

    /** Returns the optional value of Content-Length if known.

        The return value is undefined until `on_header` is called.
    */
    boost::optional<std::uint64_t>
    content_length() const
    {
        if(! (f_ & flagContentLength))
            return boost::none;
        return len_;
    }

    /** Returns `true` if the message body is chunk encoded.

        The return value is undefined until `on_header` is called.
    */
    bool
    chunked() const
    {
        return (f_ & flagChunked) != 0;
    }

    /** Returns the number of body bytes remaining in this chunk.
    */
    std::uint64_t
    remain() const
    {
        if(f_ & (flagContentLength | flagChunked))
            return len_;
        // VFALCO This is ugly
        return 65536;
    }

    /** Returns `true` if eof is needed to determine the end of message.
    */
    bool
    needs_eof() const
    {
        return ! (f_ & (flagChunked + flagContentLength));
    }

    template<class ConstBufferSequence>
    std::size_t
    write(ConstBufferSequence const& buffers, error_code& ec);

    /** Indicate that the end of stream is reached.
    */
    void
    write_eof(error_code& ec);

    /** Transfer body octets from buffer to the reader
    */
    template<class Reader, class DynamicBuffer>
    void
    write_body(Reader& r,
        DynamicBuffer& dynabuf, error_code& ec);

    /** Consume body bytes from the current chunk.
    */
    void
    consume(std::uint64_t n)
    {
        len_ -= n;
    }

private:
    inline
    Derived&
    impl()
    {
        return *static_cast<Derived*>(this);
    }

    template<class ConstBufferSequence>
    boost::string_ref
    maybe_flatten(
        ConstBufferSequence const& buffers);

    void
    parse_startline(char const*& it,
        error_code& ec, std::true_type);

    void
    parse_startline(char const*& it,
        error_code& ec, std::false_type);

    void
    parse_fields(
        char const*& it, error_code& ec);

    void
    do_field(
        boost::string_ref const& name,
            boost::string_ref const& value,
                error_code& ec);

    std::size_t
    parse_header(char const* p,
        std::size_t n, error_code& ec);

    std::size_t
    parse_chunked(char const* p,
        std::size_t n, error_code& ec);
};

} // http
} // beast

#include <beast/http/impl/new_basic_parser.ipp>

#endif
