/* Day 5 server.cpp — AUTH + LIST/GET/PUT, optional XOR on file bytes
   Build: g++ -std=c++17 server.cpp -o server
   Run:
     ./server --port 8080
     ./server --port 8080 --xor mysecretkey
*/
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace fs = std::filesystem;
const std::string SHARED_DIR = "shared_files";
const std::string USERS_FILE = "users.txt";
const size_t BUF = 4096;

struct Config {
    int port = 8080;
    bool xor_mode = false;
    std::string xor_key;
} cfg;

std::unordered_map<std::string,std::string> users;

void load_users() {
    users.clear();
    std::ifstream in(USERS_FILE);
    if (!in) {
        std::cerr << "[server] Warning: " << USERS_FILE << " not found (no users loaded)\n";
        return;
    }
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        auto p = line.find(':');
        if (p == std::string::npos) continue;
        users[line.substr(0,p)] = line.substr(p+1);
    }
}

std::string recv_line(int sock) {
    std::string s; char c;
    while (true) {
        ssize_t n = recv(sock, &c, 1, 0);
        if (n <= 0) return "";
        if (c == '\n') break;
        s.push_back(c);
    }
    return s;
}
bool send_all(int sock, const char* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock, buf + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}
bool send_line(int sock, const std::string &line) {
    std::string s = line + "\n";
    return send_all(sock, s.data(), s.size());
}

inline void xor_bytes(std::vector<char>& b, size_t n, size_t &idx, const std::string &key) {
    if (key.empty()) return;
    for (size_t i = 0; i < n; ++i) b[i] ^= key[idx++ % key.size()];
}

void handle_list(int client_sock) {
    send_line(client_sock, "OK");
    try {
        if (fs::exists(SHARED_DIR)) {
            for (auto &p : fs::directory_iterator(SHARED_DIR)) {
                if (fs::is_regular_file(p.path()))
                    send_line(client_sock, p.path().filename().string());
            }
        }
    } catch (...) {}
    send_line(client_sock, "END");
}

void handle_get(int client_sock, const std::string &filename) {
    if (filename.find('/') != std::string::npos || filename.find("..") != std::string::npos) {
        send_line(client_sock, "ERR invalid filename");
        return;
    }
    std::string path = SHARED_DIR + "/" + filename;
    if (!fs::exists(path) || !fs::is_regular_file(path)) { send_line(client_sock, "ERR not found"); return; }

    uint64_t size = fs::file_size(path);
    { std::ostringstream hdr; hdr << "OK " << size; if (!send_line(client_sock, hdr.str())) return; }

    std::ifstream in(path, std::ios::binary);
    if (!in) { send_line(client_sock, "ERR open failed"); return; }

    std::vector<char> buf(BUF);
    size_t xidx = 0;
    while (in) {
        in.read(buf.data(), buf.size());
        std::streamsize r = in.gcount();
        if (r <= 0) break;
        if (cfg.xor_mode) xor_bytes(buf, (size_t)r, xidx, cfg.xor_key);
        if (!send_all(client_sock, buf.data(), (size_t)r)) {
            std::cerr << "[server] client disconnected during send\n"; return;
        }
    }
}

void handle_put(int client_sock, const std::string &filename, uint64_t size) {
    if (filename.empty()) { send_line(client_sock, "ERR no filename"); return; }
    if (filename.find('/') != std::string::npos || filename.find("..") != std::string::npos) {
        send_line(client_sock, "ERR invalid filename"); return;
    }
    if (!fs::exists(SHARED_DIR)) fs::create_directory(SHARED_DIR);
    std::string path = SHARED_DIR + "/" + filename;

    if (!send_line(client_sock, "OK")) return; // ready signal

    std::ofstream out(path, std::ios::binary);
    if (!out) { send_line(client_sock, "ERR cannot create"); return; }

    std::vector<char> buf(BUF);
    uint64_t remaining = size;
    size_t xidx = 0;
    while (remaining > 0) {
        size_t to_read = remaining > buf.size() ? buf.size() : (size_t)remaining;
        ssize_t r = recv(client_sock, buf.data(), to_read, 0);
        if (r <= 0) { std::cerr << "[server] upload interrupted\n"; out.close(); return; }
        if (cfg.xor_mode) xor_bytes(buf, (size_t)r, xidx, cfg.xor_key);
        out.write(buf.data(), r);
        remaining -= r;
    }
    out.close();
    send_line(client_sock, "OK");
}

void handle_client(int client_sock) {
    std::cout << "[server] client connected\n";
    bool authed = false;

    while (true) {
        std::string line = recv_line(client_sock);
        if (line.empty()) break;
        std::istringstream iss(line);
        std::string cmd; iss >> cmd;

        if (cmd == "AUTH") {
            std::string u, p; iss >> u >> p;
            if (users.count(u) && users[u] == p) { authed = true; send_line(client_sock, "OK"); }
            else send_line(client_sock, "ERR invalid credentials");
        } else if (!authed) {
            send_line(client_sock, "ERR not authenticated");
        } else if (cmd == "LIST") {
            handle_list(client_sock);
        } else if (cmd == "GET") {
            std::string filename; iss >> filename;
            if (filename.empty()) send_line(client_sock, "ERR No filename");
            else handle_get(client_sock, filename);
        } else if (cmd == "PUT") {
            std::string filename; uint64_t size = 0; iss >> filename >> size;
            if (!iss || filename.empty()) send_line(client_sock, "ERR bad header");
            else handle_put(client_sock, filename, size);
        } else if (cmd == "QUIT") {
            break;
        } else if (cmd == "SELECT") {
            std::string f; iss >> f;
            if (f.empty()) send_line(client_sock, "ERR No filename provided");
            else { std::ostringstream r; r << "OK Selected " << f; send_line(client_sock, r.str()); }
        } else {
            send_line(client_sock, "ERR unknown");
        }
    }
    close(client_sock);
    std::cout << "[server] client disconnected\n";
}

int main(int argc, char* argv[]) {
    // parse args: --port N  --xor KEY
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--port" && i+1 < argc) cfg.port = std::stoi(argv[++i]);
        else if (a == "--xor" && i+1 < argc) { cfg.xor_mode = true; cfg.xor_key = argv[++i]; }
    }

    load_users();
    if (!fs::exists(SHARED_DIR)) fs::create_directory(SHARED_DIR);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }
    int opt = 1; setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = INADDR_ANY; addr.sin_port = htons(cfg.port);
    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(server_fd, 10) < 0) { perror("listen"); return 1; }
    std::cout << "Server on port " << cfg.port << (cfg.xor_mode? " [XOR enabled]\n":"\n");

    while (true) {
        sockaddr_in cli{}; socklen_t len = sizeof(cli);
        int client_sock = accept(server_fd, (sockaddr*)&cli, &len);
        if (client_sock < 0) { perror("accept"); continue; }
        // Single-threaded for simplicity; could spawn threads here.
        handle_client(client_sock);
    }
    close(server_fd);
    return 0;
}
