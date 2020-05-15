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
            [burp-clj.syntax-editor :as syntax-editor]
            [burp-clj.extender :as extender]
            [burp-clj.scripts :as scripts]
            [burp-clj.proxy :as proxy]
            [seesaw.core :as gui])
  (:import [burp ISessionHandlingAction]
           javax.swing.ComboBoxEditor
           java.awt.event.KeyEvent
           java.awt.Color
           ))

(utils/add-dep '[[clj-http "3.10.1"]])
(require '[clj-http.client :as http])

(def http-message-cols-info [{:key :index :text "#" :class java.lang.Long}
                             {:key :host :text "Host" :class java.lang.String}
                             {:key :request/url :text "URL" :class java.lang.String}
                             {:key :response/status :text "Resp.Status" :class java.lang.Long}
                             {:key :response.headers/content-length :text "Resp.Len" :class java.lang.String}
                             {:key :response.headers/content-type :text "Resp.type" :class java.lang.String}
                             {:key :port :text "PORT" :class java.lang.Long}
                             {:key :comment :text "Comment" :class java.lang.String}])



(defn get-filter-pred
  "如果是错误的过滤表达式则抛出异常,否则返回过滤表达式函数"
  [filter-exp]
  (utils/add-dep []) ;; 必须加载依赖,否则在awt线程中会执行失败！
  (let [exp (-> (format "(fn [msg] %s)" filter-exp)
                (load-string))]
    (exp {})
    exp))

(defn make-http-message-model
  [filter-pred datas]
  (let [pred-fn (try (get-filter-pred filter-pred)
                     (catch Exception e
                       (constantly false)))
        pred (fn [data]
               (helper/with-exception-default nil
                 (pred-fn data)))]
    (table/table-model :columns http-message-cols-info
                       :rows (filter pred datas))))

(defn make-syntax-combox-editor
  [syntax-text-area]
  (let [actions (atom #{})]
    (keymap/map-key syntax-text-area
                    "control ENTER" (fn [e]
                                      (doseq [a @actions]
                                        (.actionPerformed a e)))
                    :scope :self)
    (reify ComboBoxEditor
      (addActionListener [this listener]
        (swap! actions conj listener))
      (removeActionListener [this listener]
        (swap! actions disj listener))
      (getEditorComponent [this]
        syntax-text-area)
      (selectAll [this]
        (.selectAll syntax-text-area))
      (setItem [this obj]
        (.setText syntax-text-area obj))
      (getItem [this]
        (.getText syntax-text-area)))))

(defn make-ac-combox
  [{:keys [setting-key auto-completion item-validation editor-options]
    :or {item-validation identity
         editor-options [:wrap-lines? true
                         :font (font/font :font :monospaced
                                          :size 20)
                         ]}}]
  (let [datas (extender/get-setting setting-key)
        cb (gui/combobox :model datas
                         :editable? true)
        model (.getModel cb)
        editor (apply syntax-editor/syntax-text-area
                      {:auto-completion auto-completion
                       :input-map {"control P" "caret-up"
                                   "control N" "caret-down"
                                   "control B" "caret-backward"
                                   "control F" "caret-forward"
                                   "control A" "caret-begin-line"
                                   "control E" "caret-end-line"
                                   "control D" "delete-next"
                                   "control K" "RTA.DeleteRestOfLineAction"
                                   "alt K" "RTA.DeleteLineAction"
                                   "alt B" "caret-previous-word"
                                   "alt F" "caret-next-word"
                                   }}
                      editor-options)
        combox-editor (make-syntax-combox-editor editor)]
    (->> (.getSize model)
         (.insertElementAt model "clear all"))
    (.addActionListener combox-editor
                        (gui/action
                         :name "check syntax"
                         :handler (fn [e]
                                    (let [txt (gui/text e)]
                                      (cond
                                        (empty? txt)
                                        (->> (border/line-border :color Color/RED)
                                             (.setBorder editor))

                                        (= (.getElementAt model 0) txt)
                                        (->> (border/empty-border)
                                             (.setBorder editor))

                                        (item-validation txt)
                                        (do
                                          (->> (border/line-border :color Color/GREEN)
                                               (.setBorder editor))
                                          (extender/update-setting! setting-key #(cons txt %1) )
                                          (.insertElementAt model txt 0)
                                          (.setSelectedItem model txt))

                                        :else
                                        (->> (border/line-border :color Color/RED)
                                             (.setBorder editor))
                                        )))))
    (gui/listen cb :selection
                (fn [e]
                  (let [exp (gui/selection cb)]
                    (log/info "cb selection:" exp)
                    (when (and (= exp "clear all")
                               (> (.getSize model) 1))
                      (log/info "clear all filter info:" setting-key)
                      (.removeAllElements model)
                      (extender/set-setting! setting-key '())
                      (.addElement model "clear all")))))
    (.setEditor cb combox-editor)
    cb))

(defn http-message-viewer
  [{:keys [datas setting-key auto-completion-words]
    :or {auto-completion-words ["request"
                                "response"
                                "reverse"
                                "str/split"
                                "str/reverse"
                                "str/includes?"
                                "utils/try-parse-int"
                                "utils/try-parse-long"
                                "re-find"
                                "re-match"
                                "first"
                                "msg"]}}]
  (let [auto-completion-words (->> (first @datas)
                                   keys
                                   (map str)
                                   (concat  auto-completion-words))
        filter-cb (make-ac-combox {:setting-key setting-key
                                   :item-validation (fn [txt]
                                                      (try (get-filter-pred txt)
                                                           true
                                                           (catch Exception e
                                                             (gui/invoke-later
                                                              (gui/alert
                                                               (format "%s error filter expression:%s"
                                                                       txt
                                                                       e)))
                                                             false
                                                             )))
                                   :auto-completion {:use-parameter-assistance false
                                                     :trigger-key "control PERIOD"
                                                     :activate-delay 10
                                                     :init-words auto-completion-words}
                                   :editor-options [:syntax :clojure
                                                    :rows 3]
                                   })
        tbl (guix/table-x :id :http-message-table
                          :selection-mode :single
                          :model (make-http-message-model (gui/selection filter-cb) @datas))
        req-resp-controller (helper/make-request-response-controller)]
    (helper/init req-resp-controller false)
    (gui/listen tbl :selection
                (fn [e]
                  (let [v (some->> (gui/selection tbl)
                                   (table/value-at tbl))]
                    ;; (log/info :table :selection "value:" v)
                    (helper/set-message req-resp-controller v)
                    )))
    (gui/listen filter-cb :selection
                (fn [e]
                  (log/info "change model:" (gui/selection e))
                  (->> (make-http-message-model (gui/selection e) @datas)
                       (gui/config! tbl :model))))
    (bind/bind
     datas
     (bind/transform #(fn [datas]
                        (log/info "change model:" (gui/selection filter-cb))
                        (make-http-message-model (gui/selection filter-cb) datas)))
     (bind/property tbl :model))
    (gui/top-bottom-split (mig-panel
                           :items [["Filter:"]
                                   [filter-cb
                                    "wrap, grow"]
                                   [(gui/scrollable tbl)
                                    "wrap, span, grow, hmin 500, width 100%, height 100%"]])
                          (gui/left-right-split
                           (-> (helper/get-request-editor req-resp-controller)
                               (.getComponent))
                           (-> (helper/get-response-editor req-resp-controller)
                               (.getComponent))
                           :divider-location 1/2)
                          :divider-location 2/3
                          :preferred-size [1000 :by 600])))

(comment

  (def hs (extender/get-proxy-history))

  (def datas (map-indexed (fn [idx v]
                            (let [info (helper/parse-http-req-resp v)]
                              (assoc info :index idx))) hs))

  (def ds (atom datas))

  (utils/show-ui (http-message-viewer {:datas ds
                                       :setting-key :add-csrf/macro
                                       }))

  (helper/set-message e1  (first hs) )

  (helper/set-message e1  (nth hs 2) )

  (def s1 (syntax-editor/syntax-text-area
           {:auto-completion {:use-parameter-assistance true
                              :trigger-key "control PERIOD"
                              :activate-delay 10
                              :init-words ["request" "response" "defn" "reverse" "str/split"
                                           "str/reverse"]
                              :completions {:basic [{:text "test"}
                                                    {:text "tencent"
                                                     :desc "tencent test"
                                                     :summary "test text"}]}}
            :input-map {"control P" "caret-up"
                        "control N" "caret-down"
                        "control B" "caret-backward"
                        "control F" "caret-forward"
                        "control A" "caret-begine-line"
                        "control E" "caret-end-line"
                        "control D" "delete-next"
                        "alt B" "caret-previous-word"
                        "alt F" "caret-next-word"
                        }
            }
           ))


  (def acb (make-ac-combox {:setting-key :csrf-filter
                            :auto-completion {:use-parameter-assistance true
                                              :trigger-key "control PERIOD"
                                              :activate-delay 10
                                              :init-words ["request" "response" "defn" "reverse" "str/split"
                                                           "str/reverse"]
                                              :completions {:basic [{:text "test"}
                                                                    {:text "tencent"
                                                                     :desc "tencent test"
                                                                     :summary "test text"}]}}
                            :item-validation (fn [txt]
                                               (prn "validate:" txt)
                                               (try (get-filter-pred txt)
                                                    true
                                                    (catch Exception e
                                                      (gui/invoke-later
                                                       (gui/alert
                                                        (format "%s error filter expression:%s"
                                                                txt
                                                                (.getMessage e))))
                                                      false
                                                      )))
                            }))


  (utils/show-ui acb)






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
