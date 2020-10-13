(ns jslink
  (:require [burp-clj.extender :as extender]
            [burp-clj.extension-state :refer [make-unload-callback]]
            [burp-clj.scripts :as scripts]
            [burp-clj.state :as state]
            [burp-clj.utils :as utils]
            [burp-clj.validate :as validate]
            [burp-clj.helper :as helper]
            [clojure.spec.alpha :as s]
            [seesaw.core :as gui]
            [seesaw.bind :as bind]
            [seesaw.clipboard :as clip]
            [seesaw.border :as border]
            [seesaw.mig :refer [mig-panel]]
            [taoensso.timbre :as log]
            [clojure.string :as str])
  (:import [burp IScanIssue IScannerCheck IHttpRequestResponse IHttpService]))

;;;;;; link parser
(def str-delimiter "(?:\"|')")

(defn group [& args]
  (str "("
       (str/join args)
       ")"))

(def rs (-> (str str-delimiter ;; Start newline delimiter
                 (group

                  (group
                   "(?:[a-zA-Z]{1,10}://|//)" ;; Match a scheme [a-Z]*1-10 or //
                   "[^\"'/]{1,}\\." ;; Match a domainname (any character + dot)
                   "[a-zA-Z]{2,}[^\"']{0,}") ;; The domainextension and/or path

                  "|"

                  (group
                   "(?:/|\\.\\./|\\./)"             ;; Start with / or ../ or ./
                   "[^\"'><,;| *\\(\\)%$^/\\\\\\[\\]]" ;; Next character can't be...
                   "[^\"'><,;|\\(\\)]{1,}" ;; Rest of the characters can't be
                   )

                  "|"

                  (group
                   "[a-zA-Z0-9_\\-/]{1,}/" ;; Relative endpoint with /
                   "[a-zA-Z0-9_\\-/]{1,}" ;; Resource name
                   "\\.(?:[a-zA-Z]{1,4}|action)" ;; Rest + extension (length 1-4 or action)
                   "(?:[\\?|/][^\"|']{0,}|)" ;; ? mark with parameters
                   )

                  "|"

                  (group
                   "[a-zA-Z0-9_\\-/]{1,}/" ;; REST API (no extension) with /
                   "[a-zA-Z0-9_\\-/]{3,}" ;; Proper REST endpoints usually have 3+ chars
                   "(?:[\\?|#][^\"|']{0,}|)" ;; ? or # mark with parameters
                   )

                  "|"

                  (group
                   "[a-zA-Z0-9_\\-]{1,}" ;; filename
                   "\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)" ;; . + extension
                   "(?:\\?[^\"|']{0,}|)" ;; ? mark with parameters
                   ))

                 str-delimiter ;; End newline delimiter
                 )
            re-pattern))

(defn parse-links
  [s]
  (some->> (re-seq rs s)
           (map second)
           distinct))

(comment
  ;; test parse
  (defn test-parse []
    (assert (= (parse-links "\"http://example.com\"") ["http://example.com"]))
    (assert (= (parse-links "\"smb://example.com\"") ["smb://example.com"]))
    (assert (= (parse-links "\"https://www.example.co.us\"") ["https://www.example.co.us"]))
    (assert (= (parse-links "\"/path/to/file\"") ["/path/to/file"]))
    (assert (= (parse-links "\"../path/to/file\"") ["../path/to/file"]))
    (assert (= (parse-links "\"./path/to/file\"") ["./path/to/file"]))
    (assert (= (parse-links "\"/user/create.action?user=Test\"") ["/user/create.action?user=Test"]))
    (assert (= (parse-links "\"/api/create.php?user=test&pass=test#home\"") ["/api/create.php?user=test&pass=test#home"]))
    (assert (nil? (parse-links "\"/wrong/file/test<>b\"")))

    (assert (= (parse-links "\"api/create.php\"") ["api/create.php"]))
    (assert (= (parse-links "\"api/create.php?user=test\"") ["api/create.php?user=test"]))
    (assert (= (parse-links "\"api/create.php?user=test&pass=test\"") ["api/create.php?user=test&pass=test"]))
    (assert (= (parse-links "\"api/create.php?user=test#home\"") ["api/create.php?user=test#home"]))
    (assert (= (parse-links "\"user/create.action?user=Test\"") ["user/create.action?user=Test"]))
    (assert (= (parse-links "\"user/create.notaext?user=Test\"") nil))
    (assert (= (parse-links "\"/path/to/file\"") ["/path/to/file"]))
    (assert (= (parse-links "\"../path/to/file\"") ["../path/to/file"]))
    (assert (= (parse-links "\"./path/to/file\"") ["./path/to/file"]))
    (assert (= (parse-links "\"/wrong/file/test<>b\"") nil))

    (assert (= (parse-links "\"api/user\"") ["api/user"]))
    (assert (= (parse-links "\"v1/create\"") ["v1/create"]))
    (assert (= (parse-links "\"api/v1/user/2\"") ["api/v1/user/2"]))
    (assert (= (parse-links "\"api/v1/search?text=Test Hello\"") ["api/v1/search?text=Test Hello"]))
    (assert (= (parse-links "\"test_1.json\"") ["test_1.json"]))
    (assert (= (parse-links "\"test2.aspx?arg1=tmp1+tmp2&arg2=tmp3\"") ["test2.aspx?arg1=tmp1+tmp2&arg2=tmp3"]))
    (assert (= (parse-links "\"addUser.action\"") ["addUser.action"]))
    (assert (= (parse-links "\"main.js\"") ["main.js"]))
    (assert (= (parse-links "\"index.html\"") ["index.html"]))
    (assert (= (parse-links "\"robots.txt\"") ["robots.txt"]))
    (assert (= (parse-links "\"users.xml\"") ["users.xml"]))
    (assert (= (parse-links "\"UserModel.name\"") nil))
    (assert (= (set (parse-links "href=\"http://example.com\";href=\"/api/create.php\""))
               (set ["http://example.com", "/api/create.php"])))
    )

  (test-parse)
  )

;;;; burp extension helper
(def severity-type "issue严重性级别"
  {:high "High"
   :medium "Medium"
   :low "Low"
   :info "Information"
   :fp "False positive"})

(def confidence-type "issue置信度"
  {:certain "Certain"
   :firm "Firm"
   :tentative "Tentative"})

(def issue-type "issue类型"
  {:extension 0x08000000})

(s/def :issue/url #(instance? java.net.URL %1))
(s/def :issue/name string?)
(s/def :issue/type issue-type)
(s/def :issue/confidence confidence-type)
(s/def :issue/severity severity-type)
(s/def :issue/background (s/nilable string?))
(s/def :issue/detail (s/nilable string?))
(s/def :issue/remediation-background (s/nilable string?))
(s/def :issue/remediation-detail(s/nilable string?))
(s/def :issue/http-messages (s/every #(instance? IHttpRequestResponse %1)))
(s/def :issue/http-service #(instance? IHttpService %1))

(s/def :burp/issue
  (s/keys :req-un [:issue/url
                   :issue/name
                   :issue/confidence
                   :issue/severity
                   :issue/http-messages
                   :issue/http-service]
          :opt-un [:issue/background
                   :issue/detail
                   :issue/type
                   :issue/remediation-detail
                   :issue/remediation-background]))

(defn make-issue
  [info]
  {:pre (s/valid? :burp/issue info)}
  (reify IScanIssue
    (getConfidence [this] (confidence-type (:confidence info)))
    (getHttpMessages [this] (:http-messages info))
    (getHttpService [this] (:http-service info))
    (getIssueBackground [this] (:background info))
    (getIssueDetail [this] (:detail info))
    (getIssueName [this] (:name info))
    (^int getIssueType [this] (or (some-> (:type info)
                                          issue-type)
                                  (issue-type :extension)))
    (getRemediationBackground [this] (:remediation-background info))
    (getRemediationDetail [this] (:remediation-detail info))
    (getSeverity [this] (severity-type (:severity info)))
    (getUrl [this] (:url info))))

(def duplicate-issues-indication "重复扫描的issue如何处理"
  {:existing -1 ;; 保留旧的
   :both 0 ;;　两个都保留
   :new 1 ;; 保留新的
   })

(defn make-scanner-check
  "`consolidate-duplicate-fn` 如何处理同一个url的多次扫描结果，
       函数参数为[existing-issue new-issue] 返回值为#{:existing :both :new}之一
   `activate-scan-fn` 主动扫描,函数参数为[req-resp insertion-point] 返回issue列表
   `passive-scan-fn` 被动扫描，函数参数为[req-resp] 返回issue列表"
  [{:keys [consolidate-duplicate-fn
           activate-scan-fn
           passive-scan-fn]
    :or {consolidate-duplicate-fn (constantly :existing)
         activate-scan-fn (constantly nil)
         passive-scan-fn (constantly nil)}}]
  (reify IScannerCheck
    (consolidateDuplicateIssues [this existing-issue new-issue]
     (-> (consolidate-duplicate-fn existing-issue new-issue)
         duplicate-issues-indication))
    (doActiveScan [this req-resp insertion-point]
      (activate-scan-fn req-resp insertion-point))
    (doPassiveScan [this req-resp]
      (passive-scan-fn req-resp))))

;;;; scanner-check and gui
(def logs (atom ""))

(def js-exclusion-list ["jquery"
                        "google-analytics"
                        "gpt.js"])

(defn exclusion-js?
  [url]
  (some #(str/includes? url %1) js-exclusion-list))

(defn scan-resp-links
  [req-resp]
  (when (= "script"
           (-> (helper/analyze-response req-resp)
               helper/parse-mime-type
               str/lower-case))
    (->> (.getResponse req-resp)
         utils/parse-response
         :body
         parse-links)))

(defn passive-scan
  [req-resp]
  (let [service (.getHttpService req-resp)
        url (-> (.getUrl req-resp)
                str)]
    (log/info :passive-scan-check url)
    (when (str/includes? url ".js")
      (if (exclusion-js? url)
        (swap! logs str "\n[-] exclude url:" url)
        (when-let [links (scan-resp-links req-resp)]
          (->> (str "[+] scanned js links:" url)
               (conj links)
               (str/join "\n    ")
               (swap! logs str "\n"))
          (-> (make-issue {:url (.getUrl req-resp)
                           :name "js links finder"
                           :confidence :certain
                           :severity :info
                           :http-messages (into-array [req-resp])
                           :http-service service
                           :background "JS files holds links to other parts of web applications. Refer to TAB for results."
                           :remediation-background "js links finder is an <b>informational</b> finding only.<br>"
                           :detail (format "Burp Scanner has analysed the following JS file for links: <b>%s</b><br><br>" url)})
              list))))))

(defn jslink-issue-check
  []
  (make-scanner-check {:passive-scan-fn passive-scan}))

(defn make-jslink-view
  []
  (let [txt (gui/text :text ""
                      :multi-line? true
                      :editable? false)]
    (bind/bind
     logs
     (bind/property txt :text))
    (gui/scrollable txt)))



;;;; extension

(def reg (scripts/reg-script! :jslink
                              {:name "js link parse"
                               :version "0.0.1"
                               :min-burp-clj-version "0.3.6"

                               :scanner-check {:scanner-check/jslink (jslink-issue-check)}
                               ;; 添加tab
                               :tab {:jslink ;; tab的key,必须全局唯一
                                     {:captain "JS Links"
                                      :view (make-jslink-view)}}}))





