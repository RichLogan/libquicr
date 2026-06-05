// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "quicr/detail/control_messages/message_reader.h"
#include "quicr/detail/control_messages/parameters.h"

namespace quicr::messages::control {

    struct SubscribeTracks
    {
        static constexpr std::uint64_t kType = 0x51;

        const RequestID request_id;
        const TrackNamespace track_namespace_prefix;
        const std::vector<Token> auth_tokens;
        const bool forward;

        explicit SubscribeTracks(BytesSpan payload)
          : SubscribeTracks(Parse(MessageReader{ payload }))
        {
        }

      private:
        struct Parsed
        {
            RequestID request_id;
            TrackNamespace track_namespace_prefix;
            std::vector<Token> auth_tokens;
            bool forward;
        };

        explicit SubscribeTracks(Parsed p)
          : request_id(p.request_id)
          , track_namespace_prefix(std::move(p.track_namespace_prefix))
          , auth_tokens(std::move(p.auth_tokens))
          , forward(p.forward)
        {
        }

        static Parsed Parse(MessageReader reader)
        {
            Parsed p;
            p.request_id = reader.Read<RequestID>();
            p.track_namespace_prefix = reader.Read<TrackNamespace>();
            const auto params = reader.Read<Parameters>();
            reader.ExpectDone();

            ValidateParameters(params, { ParameterType::kAuthorizationToken, ParameterType::kForward });
            p.auth_tokens = CollectAuthTokens(params);
            p.forward = ResolveForward(params, true);
            return p;
        }
    };

} // namespace quicr::messages::control
