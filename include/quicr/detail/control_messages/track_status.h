// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "quicr/detail/control_messages/message_reader.h"
#include "quicr/detail/control_messages/parameters.h"

namespace quicr::messages::control {

    struct TrackStatus
    {
        static constexpr std::uint64_t kType = 0xD;

        const RequestID request_id;
        const TrackNamespace track_namespace;
        const TrackName track_name;
        const std::vector<Token> auth_tokens;

        explicit TrackStatus(BytesSpan payload)
          : TrackStatus(Parse(MessageReader{ payload }))
        {
        }

      private:
        struct Parsed
        {
            RequestID request_id;
            TrackNamespace track_namespace;
            TrackName track_name;
            std::vector<Token> auth_tokens;
        };

        explicit TrackStatus(Parsed p)
          : request_id(p.request_id)
          , track_namespace(std::move(p.track_namespace))
          , track_name(std::move(p.track_name))
          , auth_tokens(std::move(p.auth_tokens))
        {
        }

        static Parsed Parse(MessageReader reader)
        {
            Parsed p;
            p.request_id = reader.Read<RequestID>();
            p.track_namespace = reader.Read<TrackNamespace>();
            p.track_name = reader.Read<TrackName>();
            const auto params = reader.Read<Parameters>();
            reader.ExpectDone();

            ValidateParameters(params, { ParameterType::kAuthorizationToken });
            p.auth_tokens = CollectAuthTokens(params);
            return p;
        }
    };

} // namespace quicr::messages::control
