// Sample C++ for knowledge graph extraction
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <mutex>
#include <cstring>

namespace crypto {

// C4: scoped enum (enum class)
enum class KeyState { Uninitialized, Active, Revoked, Expired };

// C4: plain enum (unscoped)
enum ErrorCode { OK, InvalidKey, Timeout, InternalError };

// C1: using type alias
using KeyIndex = size_t;

struct KeyPair {
    std::string public_key;
    std::string private_key;
    KeyState state;
};

// H3: template class
template <typename T, int N>
class SecureBuffer {
public:
    T data[N];
    int count;

    void clear() {
        memset(data, 0, sizeof(data));
        count = 0;
    }
};

class KeyManager {
public:
    KeyManager(size_t max_keys) : max_keys_(max_keys) {}

    bool generate_key(const std::string& algorithm) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (keys_.size() >= max_keys_) {
            return false;
        }
        KeyPair kp;
        kp.state = KeyState::Active;
        kp.public_key = derive_public_key(algorithm);
        kp.private_key = derive_private_key(algorithm);
        keys_.push_back(std::move(kp));
        return true;
    }

    bool revoke_key(size_t index) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (index >= keys_.size()) {
            return false;
        }
        keys_[index].state = KeyState::Revoked;
        notify_revocation(index);
        return true;
    }

    // H1: const method
    const KeyPair* get_key(size_t index) const {
        if (index >= keys_.size()) {
            return nullptr;
        }
        return &keys_[index];
    }

    void rotate_keys() {
        for (size_t i = 0; i < keys_.size(); ++i) {
            if (keys_[i].state == KeyState::Active) {
                keys_[i].state = KeyState::Expired;
                generate_key("default");
            }
        }
    }

    // C2: operator overload
    bool operator==(const KeyManager& other) const {
        return max_keys_ == other.max_keys_;
    }

    virtual ~KeyManager() = default;

    // C3: friend declaration
    friend class KeyAuditor;

    // C5: static member method
    static int instance_count() {
        return instance_count_;
    }

protected:
    virtual std::string derive_public_key(const std::string& algo) {
        return "pub_" + algo;
    }

private:
    std::string derive_private_key(const std::string& algo) {
        return "priv_" + algo;
    }

    void notify_revocation(size_t index) {
        // callback to external system
        on_revoke_callback_(index);
    }

    std::vector<KeyPair> keys_;
    size_t max_keys_;
    std::mutex mutex_;
    std::function<void(size_t)> on_revoke_callback_;
    // C5: static member field
    static int instance_count_;
};

class HsmKeyManager : public KeyManager {
public:
    HsmKeyManager(size_t max_keys, const std::string& hsm_url)
        : KeyManager(max_keys), hsm_url_(hsm_url) {}

protected:
    std::string derive_public_key(const std::string& algo) override {
        return hsm_derive(algo);
    }

private:
    std::string hsm_derive(const std::string& algo) {
        // HSM call -- external system interaction
        return "hsm_pub_" + algo;
    }

    std::string hsm_url_;
};

// Free function with dangerous API calls (H5)
void unsafe_memcpy(void* dst, const void* src, size_t n) {
    memcpy(dst, src, n);
}

// H5: function calling multiple dangerous APIs
void dangerous_operations(char* buf, const char* input) {
    strcpy(buf, input);
    void* p = malloc(1024);
    free(p);
}

// H5: function with reinterpret_cast
int cast_example(void* ptr) {
    int* ip = reinterpret_cast<int*>(ptr);
    return *ip;
}

} // namespace crypto
