#include "packet/packet_element.hpp"

namespace skan::packet {

std::vector<std::uint8_t> PacketElement::serialize() const
{
    std::vector<std::uint8_t> output(serialized_size(), 0U);
    if (serialize(std::span<std::uint8_t>{output}) != core::StatusCode::Ok) {
        output.clear();
    }
    return output;
}

} // namespace skan::packet
