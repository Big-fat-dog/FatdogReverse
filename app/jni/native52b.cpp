/**
 * native52b.cpp — L52 冰封雪域（海量业务代码干扰）
 *
 * 8 个业务类，每个类 5-8 个方法，每个方法 30-50 行
 * 被 JNI_OnLoad 通过 dlopen 加载，部分函数指针注册到本地方法表做干扰
 * 与加密逻辑无关，纯干扰代码
 */

#include <jni.h>
#include <string>
#include <cstring>
#include <cstdint>
#include <vector>
#include <map>
#include <algorithm>
#include <ctime>
#include <android/log.h>

#define LOG_TAG "native52b"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// ==================== InventoryService ====================
class InventoryService {
private:
    struct Product {
        int id;
        std::string name;
        int stock;
        double price;
        int threshold;
        bool reserved;
    };
    std::vector<Product> products_;
    int syncCounter_;
    bool warehouseSynced_;

public:
    InventoryService() : syncCounter_(0), warehouseSynced_(false) {}

    bool checkStock(int productId, int quantity) {
        for (auto& p : products_) {
            if (p.id == productId) {
                if (p.stock >= quantity) {
                    LOGI("Stock check passed for product %d", productId);
                    return true;
                }
                LOGI("Stock check failed: product %d has %d, need %d", productId, p.stock, quantity);
                return false;
            }
        }
        LOGI("Product %d not found in inventory", productId);
        return false;
    }

    bool reserveStock(int productId, int quantity) {
        for (auto& p : products_) {
            if (p.id == productId && !p.reserved) {
                if (p.stock >= quantity) {
                    p.stock -= quantity;
                    p.reserved = true;
                    LOGI("Reserved %d units of product %d", quantity, productId);
                    return true;
                }
            }
        }
        return false;
    }

    bool releaseStock(int productId, int quantity) {
        for (auto& p : products_) {
            if (p.id == productId) {
                p.stock += quantity;
                p.reserved = false;
                LOGI("Released %d units of product %d", quantity, productId);
                return true;
            }
        }
        return false;
    }

    bool syncWarehouse() {
        syncCounter_++;
        if (syncCounter_ % 5 == 0) {
            warehouseSynced_ = true;
            LOGI("Warehouse synced at counter %d", syncCounter_);
            return true;
        }
        return false;
    }

    bool updateThreshold(int productId, int newThreshold) {
        for (auto& p : products_) {
            if (p.id == productId) {
                p.threshold = newThreshold;
                return true;
            }
        }
        return false;
    }

    int getStock(int productId) {
        for (const auto& p : products_) {
            if (p.id == productId) return p.stock;
        }
        return -1;
    }

    void addProduct(int id, const std::string& name, int stock, double price) {
        Product p;
        p.id = id; p.name = name; p.stock = stock;
        p.price = price; p.threshold = 10; p.reserved = false;
        products_.push_back(p);
    }

    int getProductCount() { return products_.size(); }
};

// ==================== ShippingCalculator ====================
class ShippingCalculator {
private:
    double baseRate_;
    double internationalMultiplier_;
    double discountThreshold_;
    std::map<std::string, double> zoneRates_;

public:
    ShippingCalculator() : baseRate_(10.0), internationalMultiplier_(2.5), discountThreshold_(100.0) {
        zoneRates_["domestic"] = 1.0;
        zoneRates_["international"] = 2.5;
        zoneRates_["express"] = 3.0;
    }

    double calculateDomestic(double weight, int zone) {
        double rate = baseRate_ * weight;
        if (zone > 5) rate *= 1.2;
        LOGI("Domestic shipping: weight=%.1f zone=%d rate=%.2f", weight, zone, rate);
        return rate;
    }

    double calculateInternational(double weight, const std::string& country) {
        double rate = baseRate_ * internationalMultiplier_ * weight;
        if (country.length() > 2) rate *= 1.1;
        LOGI("International shipping: weight=%.1f country=%s rate=%.2f", weight, country.c_str(), rate);
        return rate;
    }

    double applyDiscount(double total, int loyaltyLevel) {
        double discount = 0.0;
        if (loyaltyLevel > 3) discount = 0.15;
        else if (loyaltyLevel > 1) discount = 0.05;
        double result = total * (1.0 - discount);
        LOGI("Discount applied: total=%.2f loyalty=%d discount=%.0f%% result=%.2f",
             total, loyaltyLevel, discount * 100, result);
        return result;
    }

    std::string estimateArrival(int zone, bool express) {
        int days = express ? 2 : 5;
        if (zone > 3) days += 2;
        if (zone > 7) days += 3;
        return std::to_string(days) + " business days";
    }

    double getRateForZone(const std::string& zone) {
        auto it = zoneRates_.find(zone);
        if (it != zoneRates_.end()) return it->second;
        return baseRate_;
    }

    void setBaseRate(double rate) { baseRate_ = rate; }
    double getBaseRate() const { return baseRate_; }
};

// ==================== UserPreferenceStore ====================
class UserPreferenceStore {
private:
    std::map<std::string, std::string> preferences_;
    std::map<std::string, bool> notificationSettings_;
    std::string currentTheme_;
    std::string currentLanguage_;
    bool dirty_;

public:
    UserPreferenceStore() : currentTheme_("dark"), currentLanguage_("zh"), dirty_(false) {}

    bool loadPreferences(int userId) {
        preferences_["theme"] = currentTheme_;
        preferences_["language"] = currentLanguage_;
        preferences_["font_size"] = "14";
        preferences_["auto_save"] = "true";
        dirty_ = false;
        LOGI("Loaded preferences for user %d", userId);
        return true;
    }

    bool saveTheme(const std::string& theme) {
        if (theme != "dark" && theme != "light") return false;
        currentTheme_ = theme;
        preferences_["theme"] = theme;
        dirty_ = true;
        LOGI("Theme saved: %s", theme.c_str());
        return true;
    }

    bool setLanguage(const std::string& lang) {
        if (lang.length() != 2) return false;
        currentLanguage_ = lang;
        preferences_["language"] = lang;
        dirty_ = true;
        LOGI("Language set: %s", lang.c_str());
        return true;
    }

    bool getNotificationSettings(const std::string& type) {
        auto it = notificationSettings_.find(type);
        if (it != notificationSettings_.end()) return it->second;
        return true; // default enabled
    }

    void setNotificationSettings(const std::string& type, bool enabled) {
        notificationSettings_[type] = enabled;
        dirty_ = true;
    }

    std::string getPreference(const std::string& key) {
        auto it = preferences_.find(key);
        if (it != preferences_.end()) return it->second;
        return "";
    }

    void setPreference(const std::string& key, const std::string& value) {
        preferences_[key] = value;
        dirty_ = true;
    }

    bool isDirty() const { return dirty_; }
    void markClean() { dirty_ = false; }
    int getPreferenceCount() const { return preferences_.size(); }
};

// ==================== DataSyncer ====================
class DataSyncer {
private:
    int pullCount_;
    int pushCount_;
    int conflictCount_;
    bool syncInProgress_;
    std::vector<std::string> pendingRecords_;

public:
    DataSyncer() : pullCount_(0), pushCount_(0), conflictCount_(0), syncInProgress_(false) {}

    bool pullRemote(const std::string& endpoint) {
        if (syncInProgress_) return false;
        syncInProgress_ = true;
        pullCount_++;
        LOGI("Pulling from %s (attempt %d)", endpoint.c_str(), pullCount_);
        syncInProgress_ = false;
        return true;
    }

    bool pushLocal(const std::string& endpoint) {
        if (pendingRecords_.empty()) return false;
        pushCount_++;
        LOGI("Pushing %zu records to %s", pendingRecords_.size(), endpoint.c_str());
        pendingRecords_.clear();
        return true;
    }

    int resolveConflict(const std::string& recordId, const std::string& resolution) {
        conflictCount_++;
        if (resolution == "local") return 1;
        if (resolution == "remote") return 2;
        if (resolution == "merge") return 3;
        return 0;
    }

    bool mergeRecords(const std::vector<std::string>& remote,
                      const std::vector<std::string>& local) {
        int merged = 0;
        for (const auto& r : remote) {
            bool found = false;
            for (const auto& l : local) {
                if (r == l) { found = true; break; }
            }
            if (!found) merged++;
        }
        LOGI("Merged %d new records from remote", merged);
        return merged > 0;
    }

    void addPendingRecord(const std::string& record) {
        pendingRecords_.push_back(record);
    }

    int getPendingCount() const { return pendingRecords_.size(); }
    int getPullCount() const { return pullCount_; }
    int getPushCount() const { return pushCount_; }
    int getConflictCount() const { return conflictCount_; }
};

// ==================== ReportGenerator ====================
class ReportGenerator {
private:
    int reportCounter_;
    std::string lastReportType_;
    std::map<std::string, int> reportStats_;

public:
    ReportGenerator() : reportCounter_(0) {}

    std::string dailyReport(int year, int month, int day) {
        reportCounter_++;
        lastReportType_ = "daily";
        reportStats_["daily"]++;
        std::string report = "Daily report " + std::to_string(year) + "-" +
                             std::to_string(month) + "-" + std::to_string(day);
        LOGI("Generated daily report #%d", reportCounter_);
        return report;
    }

    std::string weeklySummary(int weekNumber) {
        reportCounter_++;
        lastReportType_ = "weekly";
        reportStats_["weekly"]++;
        std::string summary = "Weekly summary for week " + std::to_string(weekNumber);
        LOGI("Generated weekly summary #%d", reportCounter_);
        return summary;
    }

    bool exportCsv(const std::string& filePath, const std::vector<std::string>& data) {
        if (filePath.empty() || data.empty()) return false;
        LOGI("Exporting %zu rows to %s", data.size(), filePath.c_str());
        return true;
    }

    std::vector<std::string> generateCharts(const std::string& chartType) {
        std::vector<std::string> charts;
        if (chartType == "bar") {
            charts.push_back("bar_chart_revenue");
            charts.push_back("bar_chart_users");
        } else if (chartType == "line") {
            charts.push_back("line_chart_growth");
            charts.push_back("line_chart_retention");
        } else if (chartType == "pie") {
            charts.push_back("pie_chart_segments");
        }
        LOGI("Generated %zu %s charts", charts.size(), chartType.c_str());
        return charts;
    }

    std::string getLastReportType() const { return lastReportType_; }
    int getReportCount() const { return reportCounter_; }
    int getStats(const std::string& type) {
        auto it = reportStats_.find(type);
        return (it != reportStats_.end()) ? it->second : 0;
    }
};

// ==================== BackupManager ====================
class BackupManager {
private:
    struct BackupEntry {
        std::string id;
        std::string timestamp;
        size_t size;
        bool verified;
    };
    std::vector<BackupEntry> backups_;
    int maxBackups_;

public:
    BackupManager() : maxBackups_(10) {}

    std::string createBackup(const std::string& label) {
        if (backups_.size() >= maxBackups_) {
            backups_.erase(backups_.begin());
        }
        BackupEntry entry;
        entry.id = "backup_" + std::to_string(backups_.size() + 1);
        entry.timestamp = std::to_string(time(nullptr));
        entry.size = 1024 * (rand() % 100 + 1);
        entry.verified = false;
        backups_.push_back(entry);
        LOGI("Created backup: %s (size=%zu)", entry.id.c_str(), entry.size);
        return entry.id;
    }

    bool restoreBackup(const std::string& backupId) {
        for (const auto& b : backups_) {
            if (b.id == backupId) {
                LOGI("Restoring backup: %s", backupId.c_str());
                return true;
            }
        }
        return false;
    }

    bool verifyIntegrity(const std::string& backupId) {
        for (auto& b : backups_) {
            if (b.id == backupId) {
                b.verified = true;
                LOGI("Verified backup integrity: %s", backupId.c_str());
                return true;
            }
        }
        return false;
    }

    std::vector<std::string> listBackups() {
        std::vector<std::string> result;
        for (const auto& b : backups_) {
            result.push_back(b.id + " (" + b.timestamp + ")");
        }
        return result;
    }

    bool deleteBackup(const std::string& backupId) {
        for (auto it = backups_.begin(); it != backups_.end(); ++it) {
            if (it->id == backupId) {
                backups_.erase(it);
                LOGI("Deleted backup: %s", backupId.c_str());
                return true;
            }
        }
        return false;
    }

    size_t getBackupCount() const { return backups_.size(); }
    void setMaxBackups(int max) { maxBackups_ = max; }
};

// ==================== NotificationService ====================
class NotificationService {
private:
    struct Notification {
        std::string id;
        std::string type;
        std::string message;
        bool sent;
    };
    std::vector<Notification> queue_;
    int sendCount_;

public:
    NotificationService() : sendCount_(0) {}

    bool sendPush(const std::string& userId, const std::string& message) {
        Notification n;
        n.id = "push_" + std::to_string(sendCount_++);
        n.type = "push"; n.message = message; n.sent = true;
        queue_.push_back(n);
        LOGI("Push sent to %s: %s", userId.c_str(), message.c_str());
        return true;
    }

    bool sendEmail(const std::string& email, const std::string& subject, const std::string& body) {
        Notification n;
        n.id = "email_" + std::to_string(sendCount_++);
        n.type = "email"; n.message = subject; n.sent = true;
        queue_.push_back(n);
        LOGI("Email sent to %s: %s", email.c_str(), subject.c_str());
        return true;
    }

    bool sendSms(const std::string& phone, const std::string& message) {
        Notification n;
        n.id = "sms_" + std::to_string(sendCount_++);
        n.type = "sms"; n.message = message; n.sent = true;
        queue_.push_back(n);
        LOGI("SMS sent to %s", phone.c_str());
        return true;
    }

    bool queueBatch(const std::vector<std::string>& messages) {
        for (const auto& msg : messages) {
            Notification n;
            n.id = "batch_" + std::to_string(sendCount_++);
            n.type = "batch"; n.message = msg; n.sent = false;
            queue_.push_back(n);
        }
        LOGI("Queued %zu batch notifications", messages.size());
        return true;
    }

    int processQueue() {
        int processed = 0;
        for (auto& n : queue_) {
            if (!n.sent) {
                n.sent = true;
                processed++;
            }
        }
        return processed;
    }

    int getQueueSize() const { return queue_.size(); }
    int getSentCount() const { return sendCount_; }
    void clearQueue() { queue_.clear(); }
};

// ==================== RateLimiter ====================
class RateLimiter {
private:
    int maxRequests_;
    int windowSeconds_;
    std::map<std::string, std::vector<int>> requestLog_;
    std::map<std::string, int> cooldowns_;

public:
    RateLimiter() : maxRequests_(100), windowSeconds_(60) {}

    bool allow(const std::string& clientId) {
        auto it = requestLog_.find(clientId);
        if (it == requestLog_.end()) {
            requestLog_[clientId] = {1};
            return true;
        }
        int now = time(nullptr);
        // 清理过期记录
        auto& log = it->second;
        log.erase(std::remove_if(log.begin(), log.end(),
            [now, this](int t) { return now - t > windowSeconds_; }), log.end());
        if ((int)log.size() < maxRequests_) {
            log.push_back(now);
            return true;
        }
        return false;
    }

    bool reject(const std::string& clientId) {
        return !allow(clientId);
    }

    bool cooldown(const std::string& clientId, int seconds) {
        cooldowns_[clientId] = time(nullptr) + seconds;
        LOGI("Client %s in cooldown for %ds", clientId.c_str(), seconds);
        return true;
    }

    bool isOnCooldown(const std::string& clientId) {
        auto it = cooldowns_.find(clientId);
        if (it != cooldowns_.end()) {
            if (time(nullptr) < it->second) return true;
            cooldowns_.erase(it);
        }
        return false;
    }

    std::map<std::string, int> getStats() {
        std::map<std::string, int> stats;
        for (const auto& kv : requestLog_) {
            stats[kv.first] = kv.second.size();
        }
        return stats;
    }

    void setMaxRequests(int max) { maxRequests_ = max; }
    void setWindowSeconds(int sec) { windowSeconds_ = sec; }
};

// ==================== JNI 入口（干扰导出） ====================
static InventoryService g_inventory;
static ShippingCalculator g_shipping;
static UserPreferenceStore g_prefs;
static DataSyncer g_syncer;
static ReportGenerator g_reporter;
static BackupManager g_backup;
static NotificationService g_notifier;
static RateLimiter g_limiter;

jint JNI_OnLoad(JavaVM* vm, void*) {
    LOGI("JNI_OnLoad: L52b business modules loaded");
    // 初始化一些示例数据
    g_inventory.addProduct(1001, "Frost Crystal", 500, 29.99);
    g_inventory.addProduct(1002, "Snow Fragment", 300, 19.99);
    g_inventory.addProduct(1003, "Ice Shard", 100, 49.99);
    return JNI_VERSION_1_6;
}

// 干扰导出函数
extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Bk52_checkInventory(JNIEnv*, jobject, jint productId) {
    return g_inventory.getStock(productId);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_fatdog_reverse_Bk52_syncData(JNIEnv*, jobject, jstring endpoint) {
    // 空实现，纯干扰
    return JNI_TRUE;
}
