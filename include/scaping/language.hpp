#pragma once

namespace scaping {
enum class Language { Italian, English };
inline thread_local Language thread_language = Language::Italian;
inline Language current_language() noexcept { return thread_language; }
inline void set_language(Language value) noexcept { thread_language = value; }
inline const wchar_t* tr(const wchar_t* italian, const wchar_t* english) noexcept {
    return current_language() == Language::English ? english : italian;
}
class ScopedLanguage {
public:
    explicit ScopedLanguage(Language value) noexcept : previous_(current_language()) { set_language(value); }
    ~ScopedLanguage() { set_language(previous_); }
    ScopedLanguage(const ScopedLanguage&) = delete;
    ScopedLanguage& operator=(const ScopedLanguage&) = delete;
private:
    Language previous_;
};
}
