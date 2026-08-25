#ifndef SKAN_NET_UNIQUE_FD_HPP
#define SKAN_NET_UNIQUE_FD_HPP

namespace skan::net::detail {

class UniqueFd final {
public:
    UniqueFd() noexcept = default;
    explicit UniqueFd(int file_descriptor) noexcept : file_descriptor_(file_descriptor) {}
    ~UniqueFd() noexcept;

    UniqueFd(const UniqueFd &) = delete;
    UniqueFd &operator=(const UniqueFd &) = delete;

    UniqueFd(UniqueFd &&other) noexcept;
    UniqueFd &operator=(UniqueFd &&other) noexcept;

    int get() const noexcept { return file_descriptor_; }
    int release() noexcept;
    void reset(int file_descriptor = -1) noexcept;

private:
    int file_descriptor_{-1};
};

} // namespace skan::net::detail

#endif // SKAN_NET_UNIQUE_FD_HPP
