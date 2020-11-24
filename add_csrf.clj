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

(defn extract-csrf-token
  "按自己需求修改"
  [body]
  (some->> body
           ;; (re-find #"name=\"csrf-token\"\scontent=\"(.*)\"")
           (re-find #"name=\"csrf\"\svalue=\"(.*)\"")
           second))

(defn parse-target [req-resp]
  (let [req (-> (.getRequest req-resp)
                (utils/parse-request {:key-fn identity
                                      :val-fn identity}))
        service (-> (.getHttpService req-resp)
                    (helper/parse-http-service))]
    (merge req service)))

(defn set-csrf-token
  "设置`curr-req` csrf token"
  [curr-req csrf-target]
  (let [target (parse-target curr-req)]
    (when (and (= (:host target)
                  (:host csrf-target))
               (not= (:url target)
                     (:url csrf-target)))
      (log/info "start csrf-token request.")
      (let [csrf-token (-> (assoc csrf-target :headers (:headers target))
                           ;; 使用当前请求的headers进行替换
                           (utils/build-request-raw {:key-fn identity
                                                     :val-fn identity})
                           (->> (helper/send-http-raw2 target))
                           helper/bytes->str
                           (extract-csrf-token))]
        (if csrf-token
          (do (log/info :set-csrf-token "url:" (:url target) "csrf token:" csrf-token)
              (-> (update target :headers utils/assoc-header "X-CSRF-Token" csrf-token)
                  (utils/build-request-raw {:key-fn identity
                                            :val-fn identity})
                  (.getBytes)
                  (->> (.setRequest curr-req))))
          (log/warn :set-csrf-token "not found csrf token for:" (:url target)))))))

(def tool-scope #{:extender
                  :repeater
                  :scanner
                  :target
                  :sequencer
                  :intruder
                  })

(def csrf-target (atom nil))

(defn add-csrf-proc
  [{:keys [tool is-request msg]}]
  (when (and is-request
             (tool-scope tool))
    (when-let [target @csrf-target]
      (set-csrf-token msg target))))

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
                                                              parse-target)]
                                            (reset! csrf-target data)))])]))))

(def reg (scripts/reg-script! :add-csrf
                              {:name "add csrf header from body"
                               :version "0.2.0"
                               :min-burp-clj-version "0.4.4"
                               :http-listener {:add-csrf/http-listener
                                               (make-http-proc add-csrf-proc)}
                               :context-menu {:add-csrf/context-menu (set-url-menu)}
                               }))
