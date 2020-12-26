(ns burp-scripts.copy-request
  (:require [seesaw.core :as gui]
            [clojure.string :as str]
            [taoensso.timbre :as log]
            [burp-clj.i18n :as i18n]
            [burp-clj.context-menu :as context-menu]
            [burp-clj.extender :as extender]
            [burp-clj.http-message :as http-message]
            [burp-clj.scripts :as scripts]
            [burp-clj.helper :as helper]
            [burp-clj.utils :as utils]
            [seesaw.clipboard :as clip]
            [clojure.java.io :as io]
            [cheshire.core :as json]))

;;;;;; i18n
(def translations
  {:en {:missing       "**MISSING**"    ; Fallback for missing resources
        :script-name "Copy as Code"
        :menu-clj "Clojure"
        :menu-clj-no-cookie "Clojure(no cookie)"
        :menu-clj-no-common "Clojure(no common code)"
        :menu-clj-no-common-no-cookie "Clojure(no common code, no cookie)"
        }

   :zh {:script-name "生成请求代码"
        :menu-gen "生成请求代码"
        :menu-clj "Clojure"
        :menu-clj-no-cookie "Clojure(不含cookie)"
        :menu-clj-no-common "Clojure(不含公共代码)"
        :menu-clj-no-common-no-cookie "Clojure(不含公共代码和cookie)"
        }})

(def tr (partial i18n/app-tr translations))

;;;;;;
(def menu-context #{:message-editor-request
                    :message-viewer-request
                    :target-site-map-table
                    :proxy-history
                    :search-results
                    :intruder-attack-results})

(helper/add-dep-with-proxy '[[selmer "1.12.31"]
                             [org.apache.commons/commons-text "1.9"]])
(require '[selmer.parser :as render])
(import org.apache.commons.text.StringEscapeUtils)

(def common-escape-map {\newline "\\n"
                        \return "\\r"
                        \tab "\\t"
                        \" "\\\""
                        \\ "\\\\"})

(defonce trans-box
  (let [box (make-array String 256)]
    (doseq [x (range 0x0 0x100)]
      (aset box x (format "\\u%04x" x)))
    (doseq [x (range 0x20 0x7f)]
      (aset box x (str (char x))))

    (doseq [[k v] common-escape-map]
      (aset box (int k) v))
    box))

(defn byte->escaped-str
  [bs]
  (->> bs
       (map #(->> (bit-and 0xFF %1)
                  (aget trans-box)))
       (apply str)))

(def global-index (atom 0))

(defn format-req
  [req-resp {:keys [use-cookie]}]
  (let [{:keys [method
                body
                headers
                content-type
                charset
                url]} (http-message/parse-request (.getRequest req-resp))
        service (.getHttpService req-resp)
        host (helper/get-full-host service)
        headers (into {} headers)
        charset (or charset "UTF-8")]
    {:cookies (when use-cookie
                (some-> (:cookie headers)
                        (str/split #";\s*")
                        (->> (map #(let [[k v] (str/split %1 #"=")]
                                     {:k (str/trim k)
                                      :v (str/trim v)
                                      :domain (.getHost service)})))))
     :id (swap! global-index inc)
     :url (str host url)
     :method method
     :content-type content-type
     :body (when-not (empty? body)
             (case content-type
               "application/x-www-form-urlencoded"
               (->> (utils/->string body charset)
                    (http-message/decode-params))

               "application/json"
               (-> (utils/->string body charset)
                   (json/decode keyword))

               (vec body)))
     :headers (->> (dissoc headers
                           :content-length
                           :cookie
                           :host
                           :connection)
                   (map #(zipmap [:k :v] %1)))}))

(defn gen-code-to-clip
  [template opts msgs]
  (let [items (->> msgs
                   (map #(format-req %1 opts)))]
    (-> (render/render template
                       (assoc opts :items items)
                       {:tag-open \[
                        :tag-close \]})
        clip/contents!)))

(def clj-code-template (slurp (io/resource "copy_request_clj.tmp")))

(defn copy-request-menu []
  (context-menu/make-context-menu
   menu-context
   (fn [invocation]
     [(gui/menu :text (tr :menu-gen)
                :items [(gui/menu-item
                         :text (tr :menu-clj)
                         :listen [:action
                                  (fn [e]
                                    (->> (context-menu/get-selected-messge invocation)
                                         (gen-code-to-clip clj-code-template
                                                           {:use-cookie true
                                                            :common-code true})))])
                        (gui/menu-item
                         :text (tr :menu-clj-no-cookie)
                         :listen [:action
                                  (fn [e]
                                    (->> (context-menu/get-selected-messge invocation)
                                         (gen-code-to-clip clj-code-template
                                                           {:use-cookie false
                                                            :common-code true})))])
                        (gui/menu-item
                         :text (tr :menu-clj-no-common)
                         :listen [:action
                                  (fn [e]
                                    (->> (context-menu/get-selected-messge invocation)
                                         (gen-code-to-clip clj-code-template
                                                           {:use-cookie true
                                                            :common-code false})))])
                        (gui/menu-item
                         :text (tr :menu-clj-no-common-no-cookie)
                         :listen [:action
                                  (fn [e]
                                    (->> (context-menu/get-selected-messge invocation)
                                         (gen-code-to-clip clj-code-template
                                                           {:use-cookie false
                                                            :common-code false})))])

                        ])])))

(def reg (scripts/reg-script! :copy-request
                              {:name (tr :script-name)
                               :version "0.1.0"
                               :min-burp-clj-version "0.5.0"
                               :context-menu {:copy-request (copy-request-menu)}}))
