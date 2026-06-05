// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "quicr/detail/control_messages/message_reader.h"
#include "quicr/detail/control_messages/parameters.h"

namespace quicr::messages::control {

    struct SubscribeNamespace
    {
        static constexpr std::uint64_t kType = 0x50;

        const RequestID request_id;
        const TrackNamespace track_namespace_prefix;
        const std::vector<Token> auth_tokens;

        explicit SubscribeNamespace(BytesSpan payload)
          : SubscribeNamespace(Parse(MessageReader{ payload }))
        {
        }

      private:
        struct Parsed
        {
            RequestID request_id;
            TrackNamespace track_namespace_prefix;
            std::vector<Token> auth_tokens;
        };

        explicit SubscribeNamespace(Parsed p)
          : request_id(p.request_id)
          , track_namespace_prefix(std::move(p.track_namespace_prefix))
          , auth_tokens(std::move(p.auth_tokens))
        {
        }

        static Parsed Parse(MessageReader reader)
        {
            Parsed p;
            p.request_id = reader.Read<RequestID>();
            p.track_namespace_prefix = reader.Read<TrackNamespace>();
            const auto params = reader.Read<Parameters>();
            reader.ExpectDone();

            ValidateParameters(params, { ParameterType::kAuthorizationToken });
            p.auth_tokens = CollectAuthTokens(params);
            return p;
        }
    };

} // namespace quicr::messages::control
