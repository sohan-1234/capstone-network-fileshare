/* Day 5 client.cpp — AUTH + LIST/GET/PUT, optional XOR on file bytes
   Build: g++ -std=c++17 client.cpp -o client
   Run:
     ./client 127.0.0.1 8080
     ./client 127.0.0.1 8080 --xor mysecretkey
*/
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
const size_t BUF = 4096;

struct Config {
    std::string host = "127.0.0.1";
    int port = 8080;
    bool xor_mode = false;
    std::string xor_key;
} cfg;

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

bool do_auth(int sock, const std::string &user, const std::string &pass) {
    std::ostringstream cmd; cmd << "AUTH " << user << " " << pass;
    if (!send_line(sock, cmd.str())) return false;
    std::string resp = recv_line(sock);
    if (resp.rfind("OK",0) == 0) return true;
    std::cout << "Server: " << resp << "\n";
    return false;
}

bool do_list(int sock, std::vector<std::string> &files) {
    if (!send_line(sock, "LIST")) return false;
    std::string status = recv_line(sock);
    if (status.rfind("OK",0) != 0) { std::cout << "Server: " << status << "\n"; return false; }
    files.clear();
    while (true) {
        std::string f = recv_line(sock);
        if (f == "END" || f.empty()) break;
        files.push_back(f);
    }
    return true;
}

bool do_get(int sock, const std::string &filename, const std::string &save_as) {
    std::ostringstream cmd; cmd << "GET " << filename;
    if (!send_line(sock, cmd.str())) { std::cerr << "Send failed\n"; return false; }
    std::string hdr = recv_line(sock);
    if (hdr.rfind("OK ", 0) != 0) { std::cout << "Server: " << hdr << "\n"; return false; }
    uint64_t size = std::stoull(hdr.substr(3));
    std::ofstream out(save_as, std::ios::binary);
    if (!out) { std::cerr << "Cannot open output file\n"; return false; }

    std::vector<char> buf(BUF);
    uint64_t remaining = size;
    size_t xidx = 0;
    while (remaining > 0) {
        size_t to_read = remaining > buf.size() ? buf.size() : (size_t)remaining;
        ssize_t r = recv(sock, buf.data(), to_read, 0);
        if (r <= 0) { std::cerr << "Transfer interrupted\n"; out.close(); return false; }
        if (cfg.xor_mode) xor_bytes(buf, (size_t)r, xidx, cfg.xor_key);
        out.write(buf.data(), r);
        remaining -= r;
    }
    out.close();
    std::cout << "Downloaded to: " << save_as << "\n";
    return true;
}

bool do_put(int sock, const std::string &local_path, const std::string &remote_name) {
    if (!fs::exists(local_path) || !fs::is_regular_file(local_path)) {
        std::cout << "Local file doesn't exist: " << local_path << "\n"; return false;
    }
    uint64_t size = fs::file_size(local_path);
    std::ostringstream hdr; hdr << "PUT " << remote_name << " " << size;
    if (!send_line(sock, hdr.str())) { std::cerr << "Send failed\n"; return false; }

    std::string ready = recv_line(sock);
    if (ready.rfind("OK",0) != 0) { std::cout << "Server: " << ready << "\n"; return false; }

    std::ifstream in(local_path, std::ios::binary);
    if (!in) { std::cout << "Cannot open local file\n"; return false; }

    std::vector<char> buf(BUF);
    size_t xidx = 0;
    while (in) {
        in.read(buf.data(), buf.size());
        std::streamsize r = in.gcount();
        if (r <= 0) break;
        if (cfg.xor_mode) xor_bytes(buf, (size_t)r, xidx, cfg.xor_key);
        if (!send_all(sock, buf.data(), (size_t)r)) { std::cerr << "Upload failed\n"; return false; }
    }
    std::string done = recv_line(sock);
    if (done.rfind("OK",0) == 0) { std::cout << "Upload complete as: " << remote_name << "\n"; return true; }
    std::cout << "Server: " << done << "\n";
    return false;
}

int main(int argc, char* argv[]) {
    if (argc >= 2) cfg.host = argv[1];
    if (argc >= 3) cfg.port = std::stoi(argv[2]);
    for (int i = 3; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--xor" && i+1 < argc) { cfg.xor_mode = true; cfg.xor_key = argv[++i]; }
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }
    sockaddr_in srv{}; srv.sin_family = AF_INET; srv.sin_port = htons(cfg.port);
    inet_pton(AF_INET, cfg.host.c_str(), &srv.sin_addr);
    if (connect(sock, (sockaddr*)&srv, sizeof(srv)) < 0) { perror("connect"); close(sock); return 1; }
    std::cout << "[client] connected to " << cfg.host << ":" << cfg.port
              << (cfg.xor_mode ? " [XOR enabled]\n":"\n");

    // AUTH prompt
    std::string user, pass;
    std::cout << "Username: "; std::cin >> user;
    std::cout << "Password: "; std::cin >> pass;
    if (!do_auth(sock, user, pass)) { std::cout << "Auth failed.\n"; close(sock); return 0; }

    // LIST
    std::vector<std::string> files;
    if (!do_list(sock, files)) { std::cout << "LIST failed.\n"; send_line(sock,"QUIT"); close(sock); return 0; }
    if (!files.empty()) {
        std::cout << "Files on server:\n";
        for (size_t i = 0; i < files.size(); ++i) std::cout << (i+1) << ") " << files[i] << "\n";
    } else std::cout << "(No files on server)\n";

    // Menu
    std::cout << "\nChoose: [D]ownload, [U]pload, [Q]uit: ";
    char choice = 'Q'; std::cin >> choice; choice = std::toupper(choice);

    if (choice == 'D') {
        if (files.empty()) std::cout << "No files to download.\n";
        else {
            std::cout << "Enter number to download: ";
            int n=0; std::cin >> n;
            if (n>0 && n <= (int)files.size()) {
                std::string filename = files[n-1];
                std::cout << "Save as (Enter to keep same): ";
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                std::string save_as; std::getline(std::cin, save_as);
                if (save_as.empty()) save_as = filename;
                do_get(sock, filename, save_as);
            }
        }
    } else if (choice == 'U') {
        std::cout << "Local file path to upload: ";
        std::string local; std::cin >> local;
        std::string remote = fs::path(local).filename().string();
        std::cout << "Remote name (Enter to keep \"" << remote << "\"): ";
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::string tmp; std::getline(std::cin, tmp);
        if (!tmp.empty()) remote = tmp;
        do_put(sock, local, remote);
    }

    send_line(sock, "QUIT");
    close(sock);
    return 0;
}
