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

(def last-req (atom nil))
(defn format-req
  [req-resp {:keys [use-cookie]}]
  (reset! last-req req-resp)
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
                   (map-indexed (fn [idx msg]
                                  (-> (format-req msg opts)
                                      (assoc :id idx)))))]
    (-> (render/render template
                       {:items items}
                       {:tag-open \[
                        :tag-close \]})
        clip/contents!)))

(def clj-code-template (slurp (io/resource "copy_request_clj.tmp")))

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
                                         (gen-code-to-clip clj-code-template
                                                           {:use-cookie true})))])
                        (gui/menu-item
                         :text "Clojure(no cookie)"
                         :listen [:action
                                  (fn [e]
                                    (->> (context-menu/get-selected-messge invocation)
                                         (gen-code-to-clip clj-code-template nil)))])])])))

(def reg (scripts/reg-script! :copy-request
                              {:name (tr :script-name)
                               :version "0.1.0"
                               :min-burp-clj-version "0.5.0"
                               :context-menu {:copy-request (copy-request-menu)}}))
