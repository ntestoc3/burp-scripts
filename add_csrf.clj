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
            [burp-clj.context-menu :as context-menu]
            [burp-clj.scripts :as scripts]
            [burp-clj.message-viewer :as message-viewer]
            [burp-clj.proxy :as proxy]
            [seesaw.core :as gui]))

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

(defn get-url-host
  [url]
  (-> (java.net.URL. url)
      (.getHost)))

(defn set-csrf-token
  "设置`curr-req` csrf token"
  [curr-req csrf-url]
  (let [req-info (utils/parse-request curr-req)]
    (when (= (:host req-info)
             (get-url-host csrf-url))
        (let [resp (send-request (assoc req-info
                                        :url csrf-url
                                        :throw-exceptions false)
                                 true)
              csrf-token (extract-csrf-token (:body resp))]
          (if csrf-token
            (do (log/info :set-csrf-token "url:" (:url req-info) "csrf token:" csrf-token)
                (->> (assoc-in req-info [:headers :x-csrf-token] csrf-token)
                     (utils/build-request)
                     (.getBytes)
                     (.setRequest curr-req)))
            (do (log/warn :set-csrf-token "not found csrf token for:" (:url req-info))))))))

(def tool-scope #{:extender
                  :repeater
                  :scanner
                  :target
                  :sequencer
                  :intruder
                  })

(def csrf-url (atom nil))

(defn add-csrf-proc
  [{:keys [tool is-request msg]}]
  (when (and is-request
             (tool-scope tool))
    (when-let [url @csrf-url]
      (set-csrf-token msg url))))

(def menu-context #{:message-editor-request
                    :message-editor-response
                    :proxy-history
                    :target-site-map-tree
                    :message-viewer-request
                    :message-viewer-response})

(defn set-url-menu []
  (context-menu/make-context-menu
   menu-context
   (fn [invocation]
     (when-let [msgs (context-menu/get-selected-messge invocation)]
       [(gui/menu-item :text "Set CSRF URL"
                       :listen [:action (fn [e]
                                          (when-let [data (-> (first msgs)
                                                              (.getRequest)
                                                              utils/parse-request)]
                                            (reset! csrf-url (:url data))))])]))))

(def reg (scripts/reg-script! :add-csrf
                              {:name "add csrf header from body"
                               :version "0.1.2"
                               :min-burp-clj-version "0.3.5"
                               :http-listener {:add-csrf/http-listener
                                               (make-http-proc add-csrf-proc)}
                               :context-menu {:add-csrf/context-menu (set-url-menu)}
                               }))
