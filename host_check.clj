(ns host-check
  "检测HTTP Host头漏洞"
  (:require [burp-clj.utils :as utils]
            [burp-clj.extender :as extender]
            [burp-clj.message-viewer :as message-viewer]
            [burp-clj.context-menu :as context-menu]
            [burp-clj.scripts :as scripts]
            [burp-clj.helper :as helper]
            [burp-clj.collaborator :as bc]
            [com.climate.claypoole :as thread-pool]
            [diehard.core :as dh]
            [seesaw.core :as gui]
            [taoensso.timbre :as log]))

(def cols-info [{:key :index :text "#" :class java.lang.Long}
                {:key :full-host :text "Host" :class java.lang.String}
                {:key :request/url :text "URL" :class java.lang.String}
                {:key :response/status :text "Resp.Status" :class java.lang.Long}
                {:key :response.headers/content-length :text "Resp.Len" :class java.lang.String}
                {:key :response.headers/content-type :text "Resp.type" :class java.lang.String}
                {:key :comment :text "Comment" :class java.lang.String}
                {:key :port :text "PORT" :class java.lang.Long}
                {:key :rtt :text "RTT(ms)" :class java.lang.Double}])

(def bad-host "badhost.hostcheck.com")

(defn build-exps
  [info service]
  [(-> (assoc info :comment "bad port")
       (update :headers
               utils/update-header
               :host #(str %1 ":badport")
               {:keep-old-key true}))
   (-> (assoc info :comment "pre bad")
       (update :headers
               utils/update-header
               :host #(str %1 "prebad")
               {:keep-old-key true}))
   (-> (assoc info :comment "post bad")
       (update :headers
               utils/update-header
               :host #(str %1 ".postbad")
               {:keep-old-key true}))
   (-> (assoc info :comment "localhost")
       (update :headers
               utils/assoc-header
               :host "localhost"
               {:keep-old-key true}))
   (-> (assoc info :comment "absolute URL(bad host)")
       (update :url #(str (helper/get-full-host service) %1))
       (update :headers
               utils/assoc-header
               :host bad-host
               {:keep-old-key true}))
   (-> (assoc info :comment "absolute URL(bad get)")
       (update :url #(str "http://" bad-host %1)))
   (-> (assoc info :comment "multi host")
       (update :headers
               utils/insert-headers
               [["Host" bad-host]]))
   (-> (assoc info :comment "host line wrapping")
       (update :headers
               utils/insert-headers
               [[" Host" bad-host]]
               :host
               {:insert-before true}))
   (-> (assoc info :comment "other host headers")
       (update :headers
               utils/insert-headers
               [["X-Forwarded-Host" bad-host]
                ["X-Host" bad-host]
                ["X-Forwarded-Server" bad-host]
                ["X-HTTP-Host-Override" bad-host]
                ["Forwarded" bad-host]]))])

(defn build-request-failed-msg
  ([index req service] (build-request-failed-msg req service nil))
  ([index req service comment]
   (merge
    (helper/parse-http-service service)
    (helper/flatten-format-req-resp req :request)
    {:full-host (helper/get-full-host service)
     :request/raw req
     :index index
     :rtt -1
     :comment (str "FAILED! " comment)
     :foreground :red})))

;; 用rate-limiter 按秒限速不实际，一个请求可能很长时间
;; bulkhead也没必要，直接限制线程池数量就可以了
(def thread-pool-size 5)

(defn make-req
  [ms index r]
  (dh/with-retry {:retry-on Exception
                  :abort-on NullPointerException ;; http连接错误会造成NullPointerException
                  :delay-ms 2000                 ;; 重试前等待时间
                  :on-retry (fn [val ex]
                              (log/error "request " index "failed, retrying..." ex))
                  :on-failure (fn [_ ex]
                                (log/warn "request " index "failed!" ex)
                                (->> (build-request-failed-msg index
                                                               (:request/raw r)
                                                               (:service r)
                                                               (:comment r))
                                     (swap! ms conj)))
                  :max-retries 3}
    (log/info "start request" index)
    (let [{:keys [return time]} (utils/time-execution
                                 (dh/with-timeout {:timeout-ms 5000
                                                   :interrupt? true}
                                   (helper/send-http-raw (:request/raw r) (:service r))))]
      (-> (helper/parse-http-req-resp return)
          (assoc :comment (:comment r)
                 :rtt time
                 :index index)
          (->> (swap! ms conj))))))

(defn get-req-exp-service
  [req-resp]
  (let [req (-> (.getRequest req-resp)
                (utils/parse-request {:key-fn identity}))
        service (.getHttpService req-resp)]
    (->> (build-exps req service)
         (map (fn [data]
                {:service service
                 :comment (:comment data)
                 :request/raw (utils/build-request-raw data {:key-fn identity})})))))

(defn host-header-check
  [msgs]
  (let [ms (atom [])]
    (utils/show-ui (message-viewer/http-message-viewer
                    {:datas       ms
                     :columns     cols-info
                     :ac-words    (-> (first msgs)
                                      helper/parse-http-req-resp
                                      keys)
                     :ken-fn :index
                     :setting-key :host-check/intruder})
                   {:title "host header check"})
    (future (thread-pool/upfor thread-pool-size
                               [[index info] (->> msgs
                                                  (mapcat get-req-exp-service)
                                                  (map-indexed vector))]
                               (make-req ms index info)))))

(def menu-context #{:message-editor-request
                    :message-viewer-request
                    :target-site-map-table
                    :proxy-history})


(defn host-check-menu []
  (context-menu/make-context-menu
   menu-context
   (fn [invocation]
     [(gui/menu-item :text "Send request to Host-Header-check"
                     :enabled? true
                     :listen [:action (fn [e]
                                        (-> (context-menu/get-selected-messge invocation)
                                            (host-header-check)))])])))

(def reg (scripts/reg-script! :host-check
                              {:name "host header check"
                               :version "0.0.1"
                               :min-burp-clj-version "0.4.6"
                               :context-menu {:host-check (host-check-menu)}}))


(comment
  (def d1 (first (extender/get-proxy-history)))

  (def req (-> (.getRequest d1)
               (utils/parse-request {:key-fn identity})))

  (def req2 (update req :headers
                    utils/insert-headers
                    [["Host" "www.bing.com"]
                     ["Content-length" "1228"]]
                    :host
                    {:insert-before true}))

  (def d2 (utils/build-request-raw (assoc req2
                                          :body "test body")
                                   {:key-fn identity
                                    :fix-content-length false}))

  (def dr1 (helper/send-http-raw2 d2
                                  {:host "127.0.0.1"
                                   :port 8888
                                   :protocol "http"}))

  (def hs (extender/get-proxy-history))

  (def hs [dr1])

  (def datas (map-indexed (fn [idx v]
                            (let [info (helper/parse-http-req-resp v)]
                              (assoc info :index idx))) hs))

  (def ds (atom datas))

  (utils/show-ui (message-viewer/http-message-viewer
                  {:datas       ds
                   :columns     cols-info
                   :ac-words    (keys (first @ds))
                   :setting-key :host-check/intruder
                   }))

  )

