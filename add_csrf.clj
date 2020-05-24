(ns add-csrf
  (:require [clojure.string :as str]
            [taoensso.timbre :as log]
            [seesaw.swingx :as guix]
            [seesaw.rsyntax :as rsyntax]
            [seesaw.font :as font]
            [seesaw.table :as table]
            [seesaw.bind :as bind]
            [seesaw.mig :refer [mig-panel]]
            [seesaw.keymap :as keymap]
            [seesaw.border :as border]
            [burp-clj.utils :as utils]
            [burp-clj.helper :as helper]
            [burp-clj.extender :as extender]
            [burp-clj.ui :as ui]
            [burp-clj.http :refer [make-http-proc]]
            [burp-clj.scripts :as scripts]
            [burp-clj.message-viewer :as message-viewer]
            [burp-clj.proxy :as proxy]
            [seesaw.core :as gui])
  (:import [burp ISessionHandlingAction]))

(utils/add-dep '[[clj-http "3.10.1"]])
(require '[clj-http.client :as http])

(defn extract-csrf-token
  [body]
  (some->> body
           (re-find #"name=\"csrf-token\"\scontent=\"(.*)\"")
           second))

(defn send-request
  "`use-proxy` 是否使用burp proxy代理,方便调试"
  ([req use-proxy]
   (send-request (if use-proxy
                   (merge req {:insecure? true
                               :proxy-host "127.0.0.1"
                               :proxy-port 8080 })
                   req)))
  ([req]
   (let [r (http/request req)]
     (log/info :send-request "return:" (:status r))
     r)))

(defn set-csrf-token
  "设置`curr-req` csrf token"
  ([{:keys [follow-redirect curr-req last-req]
     :or {follow-redirect true}}]
   (when-let [resp-info (-> (.getResponse last-req)
                            (utils/parse-response))]
     (let [service (-> (.getHttpService curr-req)
                       (helper/parse-http-service))
           req-info (-> (.getRequest curr-req)
                        (utils/parse-request (= "https" (:protocol service))))
           resp (if (and follow-redirect
                         (#{301 302} (:status resp-info)))
                  ;; 重定向引发循环调用session action的问题，不容易解决，
                  ;; 自己实现发送请求,绕过burp
                  (let [location (get-in resp-info [:headers :location])]
                    (log/info :get-csrf-token "redirect to:" location)
                    (send-request (assoc req-info
                                         :url location
                                         :throw-exceptions false)))
                  resp-info)]
       (if-let [csrf-token (extract-csrf-token (:body resp))]
         (do (log/info :set-csrf-token "url:" (:url req-info) "csrf token:" csrf-token)
             (->> (assoc-in req-info [:headers :x-csrf-token] csrf-token)
                  (utils/build-request)
                  (.getBytes)
                  (.setRequest curr-req)))
         (do (log/warn :set-csrf-token "not found csrf token, response:" resp)))))))

(def state (atom {:tools-scope #{:repeater :extender}
                  :url-scope {:include #{".*" }}}))

(def scope-cols [{:key :enabled :text "Enabled" :class Boolean}
                 {:key :filter :text "Filter" :class String}])

(defn make-scope-table
  [data-atom]
  (let [table (gui/table :model (table/table-model :columns scope-cols
                                                   :rows @data-atom))]
    (bind/bind
     data-atom
     (bind/transform #(table/table-model :columns scope-cols
                                         :rows %1))
     (bind/property table :model))
    (-> (.getColumnModel table)
        (.getColumn 0)
        (.setPreferredWidth 5))
    table))

(defn scope-form
  [{:keys [title data-atom]}]
  (mig-panel
   :items [[(ui/make-header {:text title
                             :size 12
                             :bold false})
            "span, grow, wrap"]

           [(gui/button :text "Add"
                        :listen [:action
                                 (fn [e]
                                   (when-let [scope (ui/input {:title "Add scope URL"
                                                               :text "Specify regex for url match:"})]
                                     (swap! data-atom conj scope)
                                     ))])
            "grow"]

           [(gui/scrollable (source-list))
            "spany 5, grow, wrap, wmin 500"]

           [(gui/button :text "Remove"
                        :listen [:action
                                 (fn [e]
                                   (when-let [sel (-> (gui/to-root e)
                                                      (gui/select [:#script-source])
                                                      (gui/selection)
                                                      )]
                                     (log/info "remove script source:" sel)
                                     (script/remove-script-source! sel)))])
            "grow, wrap"]

           [(gui/button :text "Reload Scripts!"
                        :listen [:action (fn [e]
                                           (gui/invoke-later
                                            (script/reload-sources!)))])
            "grow,wrap"]
           ])
  )

(defn add-csrf-proc
  [{:keys [tool is-request msg]}]
  (when is-request

    ))

(def reg (scripts/reg-script! :add-csrf
                              {:name "add csrf header from body"
                               :version "0.1.0"
                               :min-burp-clj-version "0.3.1"
                               :http-listener {:add-csrf/http-listener
                                               (make-http-proc add-csrf-proc)}
                               }))
