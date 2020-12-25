(ns burp-scripts.copy-request
  (:require [seesaw.core :as gui]
            [clojure.string :as str]
            [taoensso.timbre :as log]
            [burp-clj.i18n :as i18n]
            [burp-clj.context-menu :as context-menu]
            [burp-clj.extender :as extender]
            [burp-clj.scripts :as scripts]
            [burp-clj.helper :as helper]
            [burp-clj.utils :as utils]
            [seesaw.clipboard :as clip]))

;;;;;; i18n
(def translations
  {:en {:missing       "**MISSING**"    ; Fallback for missing resources
        :script-name "Copy as Code"
        }

   :zh {:script-name "生成请求代码"
        :menu-gen "生成请求代码"
        }})

(def tr (partial i18n/app-tr translations))

;;;;;;
(def menu-context #{:message-editor-request
                    :message-viewer-request
                    :target-site-map-table
                    :proxy-history
                    :search-results
                    :intruder-attack-results})

(defmulti gen-request-code
  "生成请求代码

  `lang` 生成的语言

  `opts` 生成参数:
  - :no-cookie 不生成cookie

  `infos` 请求列表,每个请求为一个元素，[{:headers []
                                    :body \"\"
                                    :cookies {\"k\" \"v\"}
                                    :method :get
                                    :url \"https://localhost:81/test\"}
                                     ...]"
  (fn [lang opts infos]
    lang))

(defmethod gen-request-code :default [lang _ _]
  (log/error :gen-request-code "unsupport language:" lang))


(helper/add-dep-with-proxy '[[selmer "1.12.31"]
                             [org.apache.commons/commons-text "1.9"]])
(require '[selmer.parser :as render])
(import org.apache.commons.text.StringEscapeUtils)

(defmethod gen-request-code :clojure [_ {:keys [no-cookie]} infos]
  (with-out-str
    (println "(require '[clj-http.client :as client])")
    (println "(require '[clj-http.cookies :as cookies])
(import org.apache.http.impl.cookie.BasicClientCookie2)

(defn new-cookie
  [name value domain]
  (let [c (cookies/to-basic-client-cookie
           [name
            {:discard false
             :domain domain
             :path \"/\"
             :secure false,
             :expires nil #_(-> (java.time.Instant/now)
                          (.plus 10 java.time.temporal.ChronoUnit/DAYS)
                          (java.util.Date/from))
             :value value}])]
    (.setAttribute c BasicClientCookie2/DOMAIN_ATTR \"true\")
    c))

(def my-cs (clj-http.cookies/cookie-store))")
    (println "(def common-opts {:proxy-host nil
                  :proxy-port nil
                  :insecure? true
                  :cookie-policy :standard
                  :throw-exceptions false})")
    (doall
     (map-indexed
      (fn [index {:keys [headers cookies body method url domain]}]
        (do (println)
            (when (and (not no-cookie)
                       cookies)
              (doseq [[k v] cookies]
                (println "(cookies/add-cookie my-cs"
                         "(new-cookie" (pr-str k) (pr-str v) (pr-str domain)
                         "))")))
            (println (str "(def burp-" index))
            (println  "  (client/request
   (merge
    common-opts")
            (println "    {:method" method)
            (println "     :url" (pr-str url))
            (println "     :headers {")
            (doseq [[k v] headers]
              (println "              " (pr-str k) (pr-str v)))
            (println "               }")
            (when body
              (println "     :body \"" (StringEscapeUtils/escapeJava body)))
            (println "     :cookie-store my-cs")
            (println "     })))")))
      infos))))

(defn format-req
  [req-resp]
  (let [{:keys [method body headers url]} (utils/parse-request (.getRequest req-resp))
        service (.getHttpService req-resp)
        host (helper/get-full-host service)
        headers (into {} headers)
        cookies (some-> (:cookie headers)
                        (str/split #"; ")
                        (->> (map #(str/split %1 #"="))))]
    {:cookies cookies
     :url (str host url)
     :method method
     :domain (.getHost service)
     :body body
     :headers (dissoc headers
                      :content-length
                      :cookie
                      :host
                      :connection)}))

(comment
  (->> (extender/get-proxy-history)
       (take 10)
       (map format-req)
       (gen-request-code :clojure false)
       (spit "/tmp/aaa.clj"))

  )

(defn gen-code-to-clip
  [lang opts msgs]
  (->> msgs
       (map format-req)
       (gen-request-code lang opts)
       clip/contents!))

(defn copy-request-menu []
  (context-menu/make-context-menu
   menu-context
   (fn [invocation]
     [(gui/menu-item :text "test")
      (gui/menu :text (tr :menu-gen)
                :items [(gui/menu-item
                         :text "Clojure"
                         :listen [:action
                                  (fn [e]
                                    (->> (context-menu/get-selected-messge invocation)
                                         (gen-code-to-clip :clojure nil)))])
                        (gui/menu-item
                         :text "Clojure(no cookie)"
                         :listen [:action
                                  (fn [e]
                                    (->> (context-menu/get-selected-messge invocation)
                                         (gen-code-to-clip :clojure {:no-cookie true})))])])])))

(def reg (scripts/reg-script! :copy-request
                              {:name (tr :script-name)
                               :version "0.1.0"
                               :min-burp-clj-version "0.4.11"
                               :context-menu {:copy-request (copy-request-menu)}}))
