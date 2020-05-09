(ns add-csrf
  (:require [clojure.string :as str]
            [taoensso.timbre :as log]
            [burp-clj.utils :as utils]
            [burp-clj.helper :as helper]
            [burp-clj.extender :as extender]
            [burp-clj.scripts :as scripts]
            [burp-clj.proxy :as proxy])
  (:import [burp ISessionHandlingAction]
           ))

(defn extract-csrf-token
  [body]
  (some->> body
           (re-find #"name=\"csrf-token\"\scontent=\"(.*)\"")
           second))

(defn set-csrf-token
  "设置`curr-req` csrf token"
  ([{:keys [follow-redirect curr-req last-req]
     :or {follow-redirect true}}]
   (when-let [resp-info (-> (.getResponse last-req)
                            (utils/parse-response))]
     (let [req-info (-> (.getRequest curr-req)
                        (utils/parse-request))
           resp (if (and follow-redirect
                         (#{301 302} (:status resp-info)))
                  ;; 构造重定向请求
                  ;; 注意！如果在重定向后，如果这个重定向location在session handling rule里面
                  ;; 则会重复调用规则,需要exclude重定向后的地址，或者Tools Scope里面去掉Extender
                  (let [location (get-in resp-info [:headers :location])
                        req (utils/build-request {:url location
                                                  :headers (:headers req-info)})]
                    (log/info :get-csrf-token "redirect to:" location)
                    (-> (extender/make-http-req (.getHttpService curr-req)
                                                (.getBytes req))
                        (.getResponse)
                        utils/parse-response))
                  resp-info)]
       (when-let [csrf-token (extract-csrf-token (:body resp))]
         (log/info :set-csrf-token "url:" (:url req-info) "csrf token:" csrf-token)
         (->> (assoc-in req-info [:headers :x-csrf-token] csrf-token)
              (utils/build-request)
              (.getBytes)
              (.setRequest curr-req)))))))

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
                               :min-burp-clj-version "0.1.0"
                               :session-handling-action {:add-csrf/action
                                                         (make-action)}
                               }))
