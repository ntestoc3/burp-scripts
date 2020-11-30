(ns host-check
  "检测HTTP Host头漏洞"
  (:require [burp-clj.utils :as utils]
            [burp-clj.extender :as extender]
            [burp-clj.message-viewer :as message-viewer]
            [burp-clj.context-menu :as context-menu]
            [burp-clj.scripts :as scripts]
            [burp-clj.helper :as helper]
            [burp-clj.collaborator :as collaborator]
            [burp-clj.table-util :as table-util]
            [com.climate.claypoole :as thread-pool]
            [diehard.core :as dh]
            [seesaw.core :as gui]
            [taoensso.timbre :as log]
            [seesaw.table :as table]
            [burp-clj.i18n :as i18n]
            [burp-clj.issue :as issue])
  (:use com.rpl.specter))

;;;;;; i18n
(def translations
  {:en {:missing       "**MISSING**"    ; Fallback for missing resources
        :script-name "HOST header check"
        :issue {:name "HOST header check"
                :detail "Burp Scanner has analysed the following page has HOST ssrf <b>%1</b><br>
exploit type: <b>%2</b><br>"
                :background "<a href='https://portswigger.net/web-security/host-header#what-is-an-http-host-header-attack'>What is an HTTP Host header attack?</a>"
                :remediation-background "<a href='https://portswigger.net/web-security/host-header#how-to-prevent-http-host-header-attacks'>How to prevent HTTP Host header attacks</a>
<br>"}
        :payload-viewer-title "Payload Messages"
        :collaborator-viewer-title "Collaborator client"
        :col-host "Host"
        :col-url "URL"
        :col-response-status "Resp.Status"
        :col-response-len "Resp.Len"
        :col-response-type "Resp.type"
        :col-exploit-name "exploit name"
        :col-payload-id "Payload id"
        :col-result "Result"
        :col-comment "Comment"
        :col-port "PORT"
        :col-rtt "RTT(ms)"
        :found-ssrf "FOUND SSRF!"
        }

   :zh {:script-name "HOST检测"
        :payload-viewer-title "Payload消息列表"
        :collaborator-viewer-title "反连检测客户端"
        :col-host "主机"
        :col-url "URL"
        :col-response-status "响应状态码"
        :col-response-len "响应长度"
        :col-response-type "响应类型"
        :col-exploit-name "exploit名称"
        :col-payload-id "Payload id"
        :col-result "结果"
        :col-comment "注释"
        :col-port "端口"
        :col-rtt "往返时间(ms)"
        :found-ssrf "发现SSRF!"
        }})

(def tr (partial i18n/app-tr translations))

;;;;;;;;;;;

(def cols-info [{:key :index
                 :text "#"
                 :class Long}
                {:key :full-host
                 :text (tr :col-host)
                 :class String}
                {:key :request/url
                 :text (tr :col-url)
                 :class String}
                {:key :response/status
                 :text (tr :col-response-status)
                 :class Long}
                {:key :response.headers/content-length
                 :text (tr :col-response-len)
                 :class String}
                {:key :response.headers/content-type
                 :text (tr :col-response-type)
                 :class String}
                {:key :exp-name :text
                 (tr :col-exploit-name)
                 :class String}
                {:key :payload-id
                 :text (tr :col-payload-id)
                 :class String}
                {:key :result
                 :text (tr :col-result)
                 :class String}
                {:key :comment
                 :text (tr :col-comment)
                 :class String}
                {:key :port
                 :text (tr :col-port)
                 :class Long}
                {:key :rtt
                 :text (tr :col-rtt)
                 :class Double}])

(defn gen-exp-info
  "生成exp信息
  `info` 解码的request请求
  :exp-name 注释
  :bc collaborator client
  :updates 为对exp的更新函数,格式为[[update-key update-fn] ...], update-fn接受2个参数，第一个为当前的exp信息，第二个为update-key对应的value。
  "
  [info {:keys [exp-name bc updates]}]
  (let [bc-server (collaborator/get-serever-loc bc)]
    (let [payload-id (collaborator/gen-payload bc)
          new-info (assoc info
                          :exp-name exp-name
                          :payload-id payload-id
                          :payload-host (str payload-id "." bc-server))]
      (reduce
       (fn [info [update-key update-fn]]
         (update info update-key (fn [old-v]
                                   (update-fn info old-v))))
       new-info
       updates))))

(defn build-exps
  [info service bc]
  [(gen-exp-info info
                 {:exp-name "bad port"
                  :bc bc
                  :updates [[:headers (fn [exp hdrs]
                                        (utils/update-header
                                         hdrs
                                         :host #(str %1 ":" (:payload-host exp))
                                         {:keep-old-key true}))]]})
   (gen-exp-info info
                 {:exp-name "pre bad"
                  :bc bc
                  :updates [[:headers (fn [exp hdrs]
                                        (utils/update-header
                                         hdrs
                                         :host #(str (:payload-host exp) "." %1)
                                         {:keep-old-key true}))]]})
   (gen-exp-info info
                 {:exp-name "post bad"
                  :bc bc
                  :updates [[:headers (fn [exp hdrs]
                                        (utils/update-header
                                         hdrs
                                         :host #(str %1 "." (:payload-host exp))
                                         {:keep-old-key true}))]]})
   (gen-exp-info info
                 {:exp-name "localhost"
                  :bc bc
                  :updates [[:headers (fn [exp hdrs]
                                        (utils/assoc-header
                                         hdrs
                                         :host "localhost"
                                         {:keep-old-key true}))]]})
   (gen-exp-info info
                 {:exp-name "bad host"
                  :bc bc
                  :updates [[:headers (fn [exp hdrs]
                                        (utils/assoc-header
                                         hdrs
                                         :host (:payload-host exp)
                                         {:keep-old-key true}))]]})
   (gen-exp-info info
                 {:exp-name "absolute URL(bad host)"
                  :bc bc
                  :updates [[:url (fn [exp u]
                                    (str (helper/get-full-host service) u))]
                            [:headers (fn [exp hdrs]
                                        (utils/assoc-header
                                         hdrs
                                         :host (:payload-host exp)
                                         {:keep-old-key true}))]]})
   (gen-exp-info info
                 {:exp-name "absolute URL(bad get)"
                  :bc bc
                  :updates [[:url (fn [exp u]
                                    (str "http://" (:payload-host exp) u))]]})
   (gen-exp-info info
                 {:exp-name "multi host"
                  :bc bc
                  :updates [[:headers (fn [exp hdrs]
                                        (utils/insert-headers
                                         hdrs
                                         [["Host" (:payload-host exp)]]))]]})
   (gen-exp-info info
                 {:exp-name "host line wrapping"
                  :bc bc
                  :updates [[:headers (fn [exp hdrs]
                                        (utils/insert-headers
                                         hdrs
                                         [[" Host" (:payload-host exp)]]
                                         :host
                                         {:insert-before true}))]]})
   (gen-exp-info info
                 {:exp-name "other host headers"
                  :bc bc
                  :updates [[:headers (fn [exp hdrs]
                                        (utils/insert-headers
                                         hdrs
                                         (let [bad-host (:payload-host exp)]
                                           [["X-Forwarded-Host" bad-host]
                                            ["X-Host" bad-host]
                                            ["X-Forwarded-Server" bad-host]
                                            ["X-HTTP-Host-Override" bad-host]
                                            ["Forwarded" bad-host]])
                                         :host
                                         {:insert-before true}))]]})])

(defn build-request-failed-msg
  [{:keys [service comment] :as req-info}]
  (merge
   (helper/parse-http-service service)
   (helper/flatten-format-req-resp (:request/raw req-info) :request)
   (dissoc req-info :service)
   {:full-host (helper/get-full-host service)
    :rtt -1
    :comment (str "FAILED! " comment)
    :foreground :gray}))

;; 用rate-limiter 按秒限速不实际，一个请求可能很长时间
;; bulkhead也没必要，直接限制线程池数量就可以了
(def thread-pool-size 5)

(defn make-req
  [{:keys [index] :as r}]
  (dh/with-retry {:retry-on Exception
                  :abort-on NullPointerException ;; http连接错误会造成NullPointerException
                  :delay-ms 2000                 ;; 重试前等待时间
                  :on-retry (fn [val ex]
                              (log/error "request " index "failed, retrying..." ex))
                  :on-failure (fn [_ ex]
                                (log/warn "request " index "failed!" ex)
                                (build-request-failed-msg r))
                  :max-retries 3}
    (log/info "start request" index)
    (let [{:keys [return time]} (utils/time-execution
                                 (dh/with-timeout {:timeout-ms 5000
                                                   :interrupt? true}
                                   (helper/send-http-raw (:request/raw r) (:service r))))]
      (merge
       (helper/parse-http-req-resp return)
       (dissoc r :request/raw :service)
       {:rtt time
        :raw-req-resp return}))))

(defn get-req-exp-service
  [req-resp bc]
  (let [req (-> (.getRequest req-resp)
                (utils/parse-request {:key-fn identity}))
        service (.getHttpService req-resp)]
    (->> (build-exps req service bc)
         (map (fn [data]
                {:service service
                 :exp-name (:exp-name data)
                 :payload-id (:payload-id data)
                 :request/raw (utils/build-request-raw data {:key-fn identity})})))))

(defn update-table-found-payload
  [tbl payload-id]
  (let [payload-filter #(= payload-id (:payload-id %1))]
    (doseq [{:keys [raw-req-resp exp-name]} (table-util/values-by tbl payload-filter)]
      (let [url (.getUrl raw-req-resp)]
        (-> (issue/make-issue {:url url
                               :name (tr :issue/name)
                               :confidence :certain
                               :severity :medium
                               :http-messages [raw-req-resp]
                               :http-service (.getHttpService raw-req-resp)
                               :background (tr :issue/background)
                               :remediation-background (tr :issue/remediation-background)
                               :detail (tr :issue/detail url exp-name)})
            (issue/add-issue!))))
    (gui/invoke-later
     (table-util/update-by! tbl
                            payload-filter
                            #(assoc %1
                                    :result (tr :found-ssrf)
                                    :background :red)))))

(defn host-header-check
  [msgs]
  (let [bc (collaborator/create)
        msg-viewer (message-viewer/http-message-viewer
                    {:columns     cols-info
                     :ac-words    (-> (first msgs)
                                      helper/parse-http-req-resp
                                      keys)
                     :ken-fn :index
                     :setting-key :host-check/intruder})
        msg-table (gui/select msg-viewer [:#http-message-table])
        collaborator-viewer (collaborator/make-ui
                             {:collaborator bc
                              :callback #(->> (:interaction-id %1)
                                              (update-table-found-payload msg-table))})
        main-view (gui/tabbed-panel :tabs [{:title (tr :payload-viewer-title)
                                            :content msg-viewer}
                                           {:title (tr :collaborator-viewer-title)
                                            :content collaborator-viewer}])]
    (utils/show-ui main-view {:title (tr :script-name)})
    (future (thread-pool/upfor thread-pool-size
                               [[index info] (->> msgs
                                                  (mapcat #(get-req-exp-service %1 bc))
                                                  (map-indexed vector))]
                               (->> (assoc info :index index)
                                    (make-req)
                                    (table/add! msg-table))))))

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
                              {:name (tr :script-name)
                               :version "0.2.5"
                               :min-burp-clj-version "0.4.12"
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

  (utils/show-ui (message-viewer/http-message-viewer
                  {:datas       datas
                   :columns     cols-info
                   :ac-words    (keys (first @ds))
                   :setting-key :host-check/intruder
                   }))

  )

