#include <boost/regex.hpp>
#include <nlohmann/json.hpp>
#include <iostream>
#include <string>

using json = nlohmann::json;

int main() {
    json input;
    std::cin >> input;

    std::string text = input["text"];
    auto patterns = input["patterns"];

    json results = json::array();

    for (auto& p : patterns) {
        std::string name = p["name"];
        std::string pattern = p["pattern"];

        try {
            boost::regex re(pattern, boost::regex::perl);
            boost::smatch match;

            auto begin = text.cbegin();
            while (boost::regex_search(begin, text.cend(), match, re)) {
                results.push_back({
                    {"name", name},
                    {"match", match.str()},
                    {"start", match.position()},
                    {"end", match.position() + match.length()}
                });
                begin = match.suffix().first;
            }
        } catch (const boost::regex_error&) {
            // skip invalid regex (Purview will reject them anyway)
        }
    }

    std::cout << results.dump();
}
