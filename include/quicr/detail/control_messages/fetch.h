// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "quicr/detail/control_messages/message_reader.h"
#include "quicr/detail/control_messages/parameters.h"
#include "quicr/detail/ctrl_message_types.h"
#include "quicr/track_name.h"

#include <variant>

namespace quicr::messages::control {

    struct StandaloneFetch
    {
        static constexpr std::uint64_t kType = 0x16;

        const RequestID request_id;
        const FetchType fetch_type;
        const TrackNamespace track_namespace;
        const TrackName track_name;
        const Location start;
        const Location end;
        const std::vector<Token> auth_tokens;
        const std::optional<std::uint64_t> fill_timeout;
        const std::uint8_t subscriber_priority;
        const GroupOrder group_order;

        explicit StandaloneFetch(BytesSpan payload)
          : StandaloneFetch(Parse(MessageReader{ payload }))
        {
        }

      private:
        struct Parsed
        {
            RequestID request_id;
            FetchType fetch_type;
            TrackNamespace track_namespace;
            TrackName track_name;
            Location start;
            Location end;
            std::vector<Token> auth_tokens;
            std::optional<std::uint64_t> fill_timeout;
            std::uint8_t subscriber_priority;
            GroupOrder group_order;
        };

        explicit StandaloneFetch(Parsed p)
          : request_id(p.request_id)
          , fetch_type(p.fetch_type)
          , track_namespace(std::move(p.track_namespace))
          , track_name(std::move(p.track_name))
          , start(p.start)
          , end(p.end)
          , auth_tokens(std::move(p.auth_tokens))
          , fill_timeout(p.fill_timeout)
          , subscriber_priority(p.subscriber_priority)
          , group_order(p.group_order)
        {
        }

        static Parsed Parse(MessageReader reader)
        {
            Parsed p;
            p.request_id = reader.Read<RequestID>();
            p.fetch_type = ReadFetchType(reader);
            p.track_namespace = reader.Read<TrackNamespace>();
            p.track_name = reader.Read<TrackName>();
            p.start = reader.Read<Location>();
            p.end = reader.Read<Location>();
            const auto params = reader.Read<Parameters>();
            reader.ExpectDone();

            auto fetch_params = ResolveFetchParameters(params);
            p.auth_tokens = std::move(fetch_params.auth_tokens);
            p.fill_timeout = fetch_params.fill_timeout;
            p.subscriber_priority = fetch_params.subscriber_priority;
            p.group_order = fetch_params.group_order;
            return p;
        }

        static FetchType ReadFetchType(MessageReader& reader)
        {
            const auto fetch_type = static_cast<FetchType>(reader.Read<std::uint64_t>());
            switch (fetch_type) {
                case FetchType::kStandalone:
                    return fetch_type;
                default:
                    throw ProtocolViolationException("Invalid standalone FETCH type");
            }
        }
    };

    struct JoiningFetch
    {
        static constexpr std::uint64_t kType = 0x16;

        const RequestID request_id;
        const FetchType fetch_type;
        const RequestID joining_request_id;
        const std::uint64_t joining_start;
        const std::vector<Token> auth_tokens;
        const std::optional<std::uint64_t> fill_timeout;
        const std::uint8_t subscriber_priority;
        const GroupOrder group_order;

        explicit JoiningFetch(BytesSpan payload)
          : JoiningFetch(Parse(MessageReader{ payload }))
        {
        }

      private:
        struct Parsed
        {
            RequestID request_id;
            FetchType fetch_type;
            RequestID joining_request_id;
            std::uint64_t joining_start;
            std::vector<Token> auth_tokens;
            std::optional<std::uint64_t> fill_timeout;
            std::uint8_t subscriber_priority;
            GroupOrder group_order;
        };

        explicit JoiningFetch(Parsed p)
          : request_id(p.request_id)
          , fetch_type(p.fetch_type)
          , joining_request_id(p.joining_request_id)
          , joining_start(p.joining_start)
          , auth_tokens(std::move(p.auth_tokens))
          , fill_timeout(p.fill_timeout)
          , subscriber_priority(p.subscriber_priority)
          , group_order(p.group_order)
        {
        }

        static Parsed Parse(MessageReader reader)
        {
            Parsed p;
            p.request_id = reader.Read<RequestID>();
            p.fetch_type = ReadJoiningFetchType(reader);
            p.joining_request_id = reader.Read<RequestID>();
            p.joining_start = reader.Read<std::uint64_t>();
            const auto params = reader.Read<Parameters>();
            reader.ExpectDone();

            auto fetch_params = ResolveFetchParameters(params);
            p.auth_tokens = std::move(fetch_params.auth_tokens);
            p.fill_timeout = fetch_params.fill_timeout;
            p.subscriber_priority = fetch_params.subscriber_priority;
            p.group_order = fetch_params.group_order;
            return p;
        }

        static FetchType ReadJoiningFetchType(MessageReader& reader)
        {
            const auto fetch_type = static_cast<FetchType>(reader.Read<std::uint64_t>());
            switch (fetch_type) {
                case FetchType::kRelativeJoiningFetch:
                    [[fallthrough]];
                case FetchType::kAbsoluteJoiningFetch:
                    return fetch_type;
                default:
                    throw ProtocolViolationException("Invalid joining FETCH type");
            }
        }
    };

    using Fetch = std::variant<StandaloneFetch, JoiningFetch>;
    inline Fetch ReadFetch(BytesSpan payload)
    {
        auto reader = MessageReader{ payload };
        // TODO: We don't need to re-read these after we read them here.
        [[maybe_unused]] const auto request_id = reader.Read<RequestID>();
        const auto fetch_type = static_cast<FetchType>(reader.Read<std::uint64_t>());

        switch (fetch_type) {
            case FetchType::kStandalone:
                return StandaloneFetch{ payload };
            case FetchType::kRelativeJoiningFetch:
            case FetchType::kAbsoluteJoiningFetch:
                return JoiningFetch{ payload };
        }

        throw ProtocolViolationException("Invalid FETCH type");
    }

} // namespace quicr::messages::control
