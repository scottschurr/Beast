//
// Copyright (c) 2013-2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BEAST_HTTP_NEW_PARSER_HPP
#define BEAST_HTTP_NEW_PARSER_HPP

#include <beast/http/message.hpp>
#include <beast/http/new_basic_parser.hpp>
#include <utility>

namespace beast {
namespace http {

template<bool isRequest>
class new_parser
    : public new_basic_parser<isRequest,
        new_parser<isRequest>>
{
    struct req_impl_base
    {
        virtual
        ~req_impl_base() = default;

        virtual
        void
        move_to(void* p) = 0;

        virtual
        void
        on_req(
            boost::string_ref const&,
            boost::string_ref const&,
            int) = 0;

        virtual
        void
        on_field(
            boost::string_ref const&,
            boost::string_ref const&) = 0;
    };

    template<class Fields>
    class req_impl : public req_impl_base
    {
        header<true, Fields>& h_;

    public:
        req_impl(req_impl&&) = default;

        req_impl(header<true, Fields>& h)
            : h_(h)
        {
        }

        void
        move_to(void* p)
        {
            new(p) req_impl{std::move(*this)};
        }

        void
        on_req(
            boost::string_ref const& method,
            boost::string_ref const& path,
            int version) override
        {
            h_.version = version;
            h_.url = std::string(
                path.data(), path.size());
            h_.method = std::string(
                method.data(), method.size());
        }

        void
        on_field(
            boost::string_ref const& name,
            boost::string_ref const& value) override
        {
            h_.fields.insert(name, value);
        }
    };

    struct res_impl_base
    {
        virtual
        ~res_impl_base() = default;

        virtual
        void
        move_to(void* p) = 0;

        virtual
        void
        on_res(
            int,
            boost::string_ref const&,
            int) = 0;

        virtual
        void
        on_field(
            boost::string_ref const&,
            boost::string_ref const&) = 0;
    };

    template<class Fields>
    class res_impl : public res_impl_base
    {
        header<false, Fields>& h_;

    public:
        res_impl(res_impl&&) = default;

        res_impl(header<false, Fields>& h)
            : h_(h)
        {
        }

        void
        move_to(void* p)
        {
            new(p) res_impl{std::move(*this)};
        }

        void
        on_res(
            int status,
            boost::string_ref const& reason,
            int version) override
        {
            h_.status = status;
            h_.version = version;
            h_.reason = std::string(
                reason.data(), reason.size());
        }

        void
        on_field(
            boost::string_ref const& name,
            boost::string_ref const& value) override
        {
            h_.fields.insert(name, value);
        }
    };

    struct dummy_fields
    {
        void
        insert(boost::string_ref const&,
            boost::string_ref const&);
    };

    using impl_type = typename std::conditional<
        isRequest, req_impl_base, res_impl_base>::type;

    std::array<char, sizeof(typename
        std::conditional<isRequest,
            req_impl<dummy_fields>,
                res_impl<dummy_fields>>::type)> buf_;

public:
    /// `true` if this parser parses requests, `false` for responses.
    static bool constexpr is_request = isRequest;

    /// Destructor
    ~new_parser()
    {
        impl().~impl_type();
    }

    /// Constructor
    template<class Fields>
    new_parser(header<isRequest, Fields>& m)
    {
        construct(m);
    }

    /** Move constructor.

        After the move, the only valid operation
        on the moved-from object is destruction.
    */
    new_parser(new_parser&& other)
    {
        other.impl().move_to(buf_.data());
    }

    /// Copy constructor (disallowed)
    new_parser(new_parser const&) = delete;

    /// Move assignment (disallowed)
    new_parser& operator=(new_parser&&) = delete;

    /// Copy assignment (disallowed)
    new_parser& operator=(new_parser const&) = delete;

private:
    friend class new_basic_parser<isRequest, new_parser>;

    impl_type&
    impl()
    {
        // type-pun
        return *reinterpret_cast<
            impl_type*>(buf_.data());
    }

    template<class Fields>
    void
    construct(header<true, Fields>& h)
    {
        ::new(buf_.data()) req_impl<Fields>{h};
    }

    template<class Fields>
    void
    construct(header<false, Fields>& h)
    {
        ::new(buf_.data()) res_impl<Fields>{h};
    }

    void
    on_request(boost::string_ref const& method,
        boost::string_ref const& path,
            int version, error_code&)
    {
        impl().on_req(method, path, version);
    }

    void
    on_response(int status,
        boost::string_ref const& reason,
            int version, error_code& ec)
    {
        impl().on_res(status, reason, version);
    }

    void
    on_field(boost::string_ref const& name,
        boost::string_ref const& value,
            error_code&)
    {
        impl().on_field(name, value);
    }

    void
    on_header(error_code&)
    {
    }

    void
    on_chunk(std::size_t length,
        boost::string_ref const& ext,
            error_code&)
    {
    }

    void
    on_chunk_data(void const* data,
        std::size_t length, error_code&)
    {
    }
};

} // http
} // beast

#endif
