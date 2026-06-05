// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "quicr/detail/control_messages/message_reader.h"
#include "quicr/detail/control_messages/parameters.h"

namespace quicr::messages::control {

    struct PublishNamespace
    {
        static constexpr std::uint64_t kType = 0x6;

        const RequestID request_id;
        const TrackNamespace track_namespace;
        const std::vector<Token> auth_tokens;

        explicit PublishNamespace(BytesSpan payload)
          : PublishNamespace(Parse(MessageReader{ payload }))
        {
        }

      private:
        struct Parsed
        {
            RequestID request_id;
            TrackNamespace track_namespace;
            std::vector<Token> auth_tokens;
        };

        explicit PublishNamespace(Parsed p)
          : request_id(p.request_id)
          , track_namespace(std::move(p.track_namespace))
          , auth_tokens(std::move(p.auth_tokens))
        {
        }

        static Parsed Parse(MessageReader reader)
        {
            Parsed p;
            p.request_id = reader.Read<RequestID>();
            p.track_namespace = reader.Read<TrackNamespace>();
            const auto params = reader.Read<Parameters>();
            reader.ExpectDone();

            ValidateParameters(params, { ParameterType::kAuthorizationToken });
            p.auth_tokens = CollectAuthTokens(params);
            return p;
        }
    };

} // namespace quicr::messages::control
