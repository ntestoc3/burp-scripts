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
            [seesaw.clipboard :as clip]
            [clojure.java.io :as io]))

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

(helper/add-dep-with-proxy '[[de.ubercode.clostache/clostache "1.4.0"]
                             [org.apache.commons/commons-text "1.9"]])
(require '[clostache.parser :as render2])
(import org.apache.commons.text.StringEscapeUtils)

(defn format-req
  [req-resp {:keys [use-cookie]}]
  (let [{:keys [method body headers url]} (utils/parse-request (.getRequest req-resp))
        service (.getHttpService req-resp)
        host (helper/get-full-host service)
        headers (into {} headers)]
    {:cookies (when use-cookie
                (some-> (:cookie headers)
                        (str/split #";")
                        (->> (map #(let [[k v] (str/split %1 #"=")]
                                     {:k (str/trim k)
                                      :v (str/trim v)
                                      :domain (.getHost service)})))))
     :url (str host url)
     :method method
     :body (StringEscapeUtils/escapeJava body)
     :headers (->> (dissoc headers
                           :content-length
                           :cookie
                           :host
                           :connection)
                   (map #(zipmap [:k :v] %1)))}))

(defn gen-code-to-clip
  [template opts msgs]
  (utils/add-dep [])
  (let [items (->> msgs
                   (map-indexed (fn [idx msg]
                                  (-> (format-req msg opts)
                                      (assoc :id idx)))))]
    (-> (render2/render template {:items items})
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
                                         (gen-code-to-clip clj-code-template nil)))])
                        (gui/menu-item
                         :text "Clojure(no cookie)"
                         :listen [:action
                                  (fn [e]
                                    (->> (context-menu/get-selected-messge invocation)
                                         (gen-code-to-clip clj-code-template {:no-cookie true})))])])])))

(def reg (scripts/reg-script! :copy-request
                              {:name (tr :script-name)
                               :version "0.1.0"
                               :min-burp-clj-version "0.4.11"
                               :context-menu {:copy-request (copy-request-menu)}}))
