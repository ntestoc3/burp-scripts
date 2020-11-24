(ns host-check
  (:require [burp-clj.utils :as utils]
            [burp-clj.extender :as extender]
            [burp-clj.message-viewer :as message-viewer]
            [burp-clj.context-menu :as context-menu]
            [burp-clj.scripts :as scripts]
            [burp-clj.helper :as helper]
            [seesaw.core :as gui]
            [taoensso.timbre :as log]))


(def cols-info [{:key :index :text "#" :class java.lang.Long}
                {:key :full-host :text "Host" :class java.lang.String}
                {:key :request/url :text "URL" :class java.lang.String}
                {:key :response/status :text "Resp.Status" :class java.lang.Long}
                {:key :response.headers/content-length :text "Resp.Len" :class java.lang.String}
                {:key :response.headers/content-type :text "Resp.type" :class java.lang.String}
                {:key :port :text "PORT" :class java.lang.Long}
                {:key :comment :text "Comment" :class java.lang.String}])

(defonce ms (atom nil))

(defn host-check
  [msgs]
  (reset! ms msgs))

(def menu-context #{:message-editor-request
                    :message-viewer-request
                    :target-site-map-table
                    :proxy-history})


(defn host-check-menu []
  (context-menu/make-context-menu
   menu-context
   (fn [invocation]
     [(gui/menu-item :text "Send request to host-check"
                     :enabled? true
                     :listen [:action (fn [e]
                                        (-> (context-menu/get-selected-messge invocation)
                                            (host-check)))])])))

(def reg (scripts/reg-script! :host-check
                              {:name "host header check"
                               :version "0.0.1"
                               :min-burp-clj-version "0.4.4"
                               :context-menu {:host-check (host-check-menu)}}))


(comment
  (def d1 (first @ms))

  (def req (-> (.getRequest d1)
               (utils/parse-request {:key-fn identity})))

  (def req2 (update req :headers
                    utils/insert-headers
                    [["Host" "www.bing.com"]]
                    :host
                    {:insert-before true}))

  (def d2 (utils/build-request-raw req2 {:key-fn identity}))

  (def dr1 (helper/send-http-raw (.getHttpService d1) d2))

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

