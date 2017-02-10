//
// Copyright (c) 2013-2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BEAST_HTTP_DETAIL_NEW_PARSER_HPP
#define BEAST_HTTP_DETAIL_NEW_PARSER_HPP

#include <beast/http/message.hpp>
#include <boost/utility/string_ref.hpp>
#include <utility>

namespace beast {
namespace http {
namespace detail {

class new_parser_base
{
protected:
    // type-erasure helpers

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
};

} // detail
} // http
} // beast

#endif
