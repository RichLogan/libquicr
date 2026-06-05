// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "quicr/detail/control_messages/message_reader.h"
#include "quicr/detail/control_messages/parameters.h"

namespace quicr::messages::control {

    struct SubscribeOk
    {
        static constexpr std::uint64_t kType = 0x4;

        const TrackAlias track_alias;
        const std::optional<std::uint64_t> expires;
        const std::optional<Location> largest_object;
        const TrackExtensions track_properties;

        explicit SubscribeOk(BytesSpan payload)
          : SubscribeOk(Parse(MessageReader{ payload }))
        {
        }

      private:
        struct Parsed
        {
            TrackAlias track_alias;
            std::optional<std::uint64_t> expires;
            std::optional<Location> largest_object;
            TrackExtensions track_properties;
        };

        explicit SubscribeOk(Parsed p)
          : track_alias(p.track_alias)
          , expires(p.expires)
          , largest_object(p.largest_object)
          , track_properties(std::move(p.track_properties))
        {
        }

        static Parsed Parse(MessageReader reader)
        {
            Parsed p;
            p.track_alias = reader.Read<TrackAlias>();
            const auto params = reader.Read<Parameters>();
            p.track_properties = reader.Read<TrackExtensions>();
            reader.ExpectDone();

            ValidateParameters(params, { ParameterType::kExpires, ParameterType::kLargestObject });

            p.expires = ResolveExpires(params);
            p.largest_object = params.GetOptional<Location>(ParameterType::kLargestObject);
            return p;
        }
    };

} // namespace quicr::messages::control
