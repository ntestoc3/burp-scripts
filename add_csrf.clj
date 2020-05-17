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
            [burp-clj.scripts :as scripts]
            [burp-clj.message-viewer :as message-viewer]
            [burp-clj.proxy :as proxy]
            [seesaw.core :as gui])
  (:import [burp ISessionHandlingAction]))

(utils/add-dep '[[clj-http "3.10.1"]])
(require '[clj-http.client :as http])

(def cols-info [{:key :index :text "#" :class java.lang.Long}
                {:key :host :text "Host" :class java.lang.String}
                {:key :request/url :text "URL" :class java.lang.String}
                {:key :response/status :text "Resp.Status" :class java.lang.Long}
                {:key :response.headers/content-length :text "Resp.Len" :class java.lang.String}
                {:key :response.headers/content-type :text "Resp.type" :class java.lang.String}
                {:key :port :text "PORT" :class java.lang.Long}
                {:key :comment :text "Comment" :class java.lang.String}])


(comment

  (def hs (extender/get-proxy-history))

  (def datas (map-indexed (fn [idx v]
                            (let [info (helper/parse-http-req-resp v)]
                              (assoc info :index idx))) hs))

  (def ds (atom datas))

  (utils/show-ui (message-viewer/http-message-viewer
                  {:datas ds
                   :columns cols-info
                   :setting-key :add-csrf/macro
                   }))

  (helper/set-message e1  (first hs) )

  (helper/set-message e1  (nth hs 2) )


  )

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

(defn make-action
  []
  (reify ISessionHandlingAction
    (getActionName [this]
      "add X-CSRF-Token")
    (performAction [this curr-req macros]
      (when-let [last (last macros)]
        (set-csrf-token {:curr-req curr-req
                         :last-req last})))))

(def reg (scripts/reg-script! :add-csrf
                              {:name "add csrf header from body"
                               :version "0.0.1"
                               :min-burp-clj-version "0.3.1"
                               :session-handling-action {:add-csrf/action
                                                         (make-action)}
                               }))
