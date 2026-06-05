// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "quicr/detail/control_messages/message_reader.h"
#include "quicr/detail/control_messages/parameters.h"

namespace quicr::messages::control {

    struct Publish
    {
        static constexpr std::uint64_t kType = 0x1D;

        const RequestID request_id;
        const TrackNamespace track_namespace;
        const TrackName track_name;
        const TrackAlias track_alias;
        const std::vector<Token> auth_tokens;
        const std::optional<std::uint64_t> expires;
        const std::optional<Location> largest_object;
        const bool forward;
        const TrackExtensions track_properties;

        explicit Publish(BytesSpan payload)
          : Publish(Parse(MessageReader{ payload }))
        {
        }

      private:
        struct Parsed
        {
            RequestID request_id;
            TrackNamespace track_namespace;
            TrackName track_name;
            TrackAlias track_alias;
            std::vector<Token> auth_tokens;
            std::optional<std::uint64_t> expires;
            std::optional<Location> largest_object;
            bool forward;
            TrackExtensions track_properties;
        };

        explicit Publish(Parsed p)
          : request_id(p.request_id)
          , track_namespace(std::move(p.track_namespace))
          , track_name(std::move(p.track_name))
          , track_alias(p.track_alias)
          , auth_tokens(std::move(p.auth_tokens))
          , expires(p.expires)
          , largest_object(p.largest_object)
          , forward(p.forward)
          , track_properties(std::move(p.track_properties))
        {
        }

        static Parsed Parse(MessageReader reader)
        {
            Parsed p;
            p.request_id = reader.Read<RequestID>();
            p.track_namespace = reader.Read<TrackNamespace>();
            p.track_name = reader.Read<TrackName>();
            p.track_alias = reader.Read<TrackAlias>();
            const auto params = reader.Read<Parameters>();
            p.track_properties = reader.Read<TrackExtensions>();
            reader.ExpectDone();

            ValidateParameters(params,
                               { ParameterType::kAuthorizationToken,
                                 ParameterType::kExpires,
                                 ParameterType::kLargestObject,
                                 ParameterType::kForward });

            p.auth_tokens = CollectAuthTokens(params);
            const auto expires = params.GetOptional<std::uint64_t>(ParameterType::kExpires);
            p.expires = (expires.has_value() && expires.value() != 0) ? expires : std::nullopt;
            p.largest_object = params.GetOptional<Location>(ParameterType::kLargestObject);
            p.forward = ResolveForward(params, true);
            return p;
        }
    };

} // namespace quicr::messages::control
