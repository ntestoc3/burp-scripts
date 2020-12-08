(ns jslink
  (:require [burp-clj.extender :as extender]
            [burp-clj.scripts :as scripts]
            [burp-clj.state :as state]
            [burp-clj.utils :as utils]
            [burp-clj.validate :as validate]
            [burp-clj.helper :as helper]
            [burp-clj.issue :as issue]
            [burp-clj.i18n :as i18n]
            [seesaw.core :as gui]
            [seesaw.bind :as bind]
            [seesaw.clipboard :as clip]
            [seesaw.border :as border]
            [seesaw.mig :refer [mig-panel]]
            [taoensso.timbre :as log]
            [clojure.string :as str]
            [seesaw.table :as table]
            [burp-clj.context-menu :as context-menu])
  (:import [javax.swing.event TableModelEvent TableModelListener]))

;;; Credit to https://github.com/GerbenJavado/LinkFinder for the idea and regex

;;;;;; i18n
(def translations
  {:en {:missing       "**MISSING**"    ; Fallback for missing resources
        :script-name "js link parse"
        :issue {:name "js link parse"
                :detail "Burp Scanner has analysed the following JS file contains %1 links: <b>%2</b><br><br>"
                :background "JS files holds links to other parts of web applications. Refer to TAB for results."
                :remediation-background "js links finder is an <b>informational</b> finding only.<br>"}
        :copy "Copy"
        :copy-tip "Copy selected links"
        :copy-all "Copy All"
        :copy-all-tip "Copy all links"
        :delete "Delete"
        :delete-tip "Delete selected links(Temporarily delete the link displayed in the list)"
        :delete-selection "Delete selection"
        :delete-selection-tip "Delete selected links(Temporarily delete)"
        :delete-leading "Remove leadding [./]"
        :delete-leading-tip "Remove the leadding [./] character of all links"
        :total "Total:"
        :menu-jslink "Send Responses to js link parse"
        }

   :zh {
        ;; issue显示中文乱码
        :script-name "js链接查找"
        :copy "复制"
        :copy-tip "复制选中链接"
        :copy-all "全部复制"
        :copy-all-tip "复制所有链接"
        :delete "删除"
        :delete-tip "删除选中链接(临时删除列表中显示的链接)"
        :delete-selection "删除选中"
        :delete-selection-tip "删除选中链接(临时删除)"
        :delete-leading "删除链接前的./字符"
        :delete-leading-tip "删除所有链接最开头的./字符"
        :total "总计:"
        :menu-jslink "发送到js link parse分析Response"
        }})

(def tr (partial i18n/app-tr translations))

;;;;;; link parser
(def str-delimiter "(?:\"|')")

(defn group [& args]
  (str "(" (str/join args) ")"))

(def rs (-> (str str-delimiter ;; Start newline delimiter
                 (group

                  (group
                   "(?:[a-zA-Z]{1,10}://|//)" ;; Match a scheme [a-Z]*1-10 or //
                   "[^\"'/]{1,}\\." ;; Match a domainname (any character + dot)
                   "[a-zA-Z]{2,}[^\"']{0,}") ;; The domainextension and/or path

                  "|"

                  (group
                   "(?:/|\\.\\./|\\./)"             ;; Start with / or ../ or ./
                   "[^\"'><,;| *\\(\\)%$^/\\\\\\[\\]]" ;; Next character can't be...
                   "[^\"'><,;|\\(\\)]{1,}" ;; Rest of the characters can't be
                   )

                  "|"

                  (group
                   "[a-zA-Z0-9_\\-/]{1,}/" ;; Relative endpoint with /
                   "[a-zA-Z0-9_\\-/]{1,}" ;; Resource name
                   "\\.(?:[a-zA-Z]{1,4}|action)" ;; Rest + extension (length 1-4 or action)
                   "(?:[\\?|/][^\"|']{0,}|)" ;; ? mark with parameters
                   )

                  "|"

                  (group
                   "[a-zA-Z0-9_\\-/]{1,}/" ;; REST API (no extension) with /
                   "[a-zA-Z0-9_\\-/]{3,}" ;; Proper REST endpoints usually have 3+ chars
                   "(?:[\\?|#][^\"|']{0,}|)" ;; ? or # mark with parameters
                   )

                  "|"

                  (group
                   "[a-zA-Z0-9_\\-]{1,}" ;; filename
                   "\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)" ;; . + extension
                   "(?:\\?[^\"|']{0,}|)" ;; ? mark with parameters
                   ))

                 str-delimiter ;; End newline delimiter
                 )
            re-pattern))

(defn parse-links
  [s]
  (some->> (re-seq rs s)
           (map second)
           set))

;;;; scanner check and gui
(defonce logs (atom {}))

(def js-exclusion-list ["jquery"
                        "google-analytics"
                        "gpt.js"])

(defn exclusion-js?
  [url]
  (some #(str/includes? url %1) js-exclusion-list))

(defn scan-resp-links
  [req-resp]
  (when (= "script"
           (-> (helper/analyze-response req-resp)
               helper/parse-mime-type
               str/lower-case))
    (->> (.getResponse req-resp)
         utils/parse-response
         :body
         parse-links)))

(defn passive-scan
  [req-resp]
  (let [service (.getHttpService req-resp)
        url (-> (.getUrl req-resp)
                str)]
    (when (str/includes? url ".js")
      (if (exclusion-js? url)
        (log/info "[jslink] exclude url:" url)
        (when-let [links (scan-resp-links req-resp)]
          (swap! logs assoc url links)
          (-> (issue/make-issue {:url (.getUrl req-resp)
                                 :name (tr :issue/name)
                                 :confidence :certain
                                 :severity :info
                                 :http-messages [req-resp]
                                 :http-service service
                                 :background (tr :issue/background)
                                 :remediation-background (tr :issue/remediation-background)
                                 :detail (tr :issue/detail (count links) url)})
              list))))))

(def menu-context #{:message-editor-response
                    :message-viewer-response
                    :intruder-attack-results
                    :target-site-map-table
                    :proxy-history})

(defn jslink-menu []
  (context-menu/make-context-menu
   menu-context
   (fn [invocation]
     [(gui/menu-item :text (tr :menu-jslink)
                     :enabled? true
                     :listen [:action (fn [_]
                                        (future
                                          (->> (context-menu/get-selected-messge invocation)
                                               (pmap passive-scan))))])])))

(defn jslink-issue-check
  []
  (issue/make-scanner-check {:passive-scan-fn passive-scan}))

(defn make-links-model
  [links]
  (table/table-model :columns [{:key :link :text "link"}]
                     :rows (map #(hash-map :link %1) links)))

(defn make-jslink-view
  []
  (let [url-list (gui/listbox :model (sort (keys @logs)))
        link-list (gui/table :id :link-list)
        copy-links-fn (fn [rows]
                        (->> (table/value-at link-list rows)
                             (map :link)
                             (str/join "\n")
                             (clip/contents!)))
        remove-select-fn (fn [e]
                           (->> (gui/selection link-list {:multi? true})
                                sort
                                (apply table/remove-at! link-list)))
        link-list-row-indexes (fn []
                                (->> (table/row-count link-list)
                                     range))
        update-leadings-fn (fn []
                             (doseq [row (link-list-row-indexes)]
                               (let [new-link (-> (table/value-at link-list row)
                                                  :link
                                                  (str/replace #"^[^a-zA-Z0-9_]+" ""))]
                                 (table/update-at! link-list row {:link new-link}))))
        find-empty-or-dup-rows (fn []
                                 (->> (link-list-row-indexes)
                                      (reduce (fn [[empty-or-dup-rows uniq-links] row]
                                                (let [l (-> (table/value-at link-list row)
                                                            :link)]
                                                  (if (or (empty? l)
                                                          (uniq-links l))
                                                    [(conj empty-or-dup-rows row) uniq-links]
                                                    [empty-or-dup-rows (conj uniq-links l)])))
                                              [[] #{}])
                                      first))
        remove-all-leading (fn [e]
                             (update-leadings-fn)
                             (let [empty-or-dup-rows (find-empty-or-dup-rows)]
                               (when-not (empty? empty-or-dup-rows)
                                 (apply table/remove-at! link-list empty-or-dup-rows)))
                             (-> (.getModel link-list)
                                 (.fireTableDataChanged)))

        copy-action (gui/action :handler (fn [e]
                                           (-> (gui/selection link-list {:multi? true})
                                               copy-links-fn))
                                :name (tr :copy)
                                :enabled? false
                                :tip (tr :copy-tip))
        remove-action (gui/action :handler remove-select-fn
                                  :name (tr :delete)
                                  :enabled? false
                                  :tip (tr :delete-tip))
        copy-all-action (gui/action :handler (fn [e]
                                               (-> (table/row-count link-list)
                                                   range
                                                   copy-links-fn))
                                    :name (tr :copy-all)
                                    :tip (tr :copy-all-tip))
        link-list-panel  (mig-panel
                          :constraints [""
                                        "[][fill,grow]"
                                        "[][fill,grow]"]
                          :items [[(tr :total)]
                                  [(gui/label :id :lbl-total
                                              :text "")]
                                  [(gui/button :text (tr :delete-selection)
                                               :tip (tr :delete-selection-tip)
                                               :listen [:action remove-select-fn])]
                                  [(gui/button :text (tr :delete-leading)
                                               :tip (tr :delete-leading-tip)
                                               :listen [:action remove-all-leading])
                                   "wrap, growx"]

                                  [(gui/scrollable link-list)
                                   "span, grow"]])
        update-total-label (fn [e]
                             (-> (gui/select link-list-panel [:#lbl-total])
                                 (gui/config! :text (table/row-count link-list))))]
    (.setTableHeader link-list nil)
    (.setAutoCreateRowSorter link-list true)
    (bind/bind
     logs
     (bind/transform (comp sort keys))
     (bind/property url-list :model))
    (gui/config! link-list :popup
                 (gui/popup
                  :items [copy-action
                          copy-all-action
                          (gui/separator)
                          remove-action]))
    (gui/listen url-list :selection
                (fn [e]
                  (let [add-model-listener (fn [model]
                                             (->> (utils/table-model-listener update-total-label)
                                                  (.addTableModelListener model))
                                             model)]
                    (some->> (gui/selection url-list {:multi? true})
                             (select-keys @logs)
                             vals
                             (reduce into #{})
                             make-links-model
                             add-model-listener
                             (gui/config! link-list :model))
                    (update-total-label nil)
                    (-> (.getRowSorter link-list)
                        (.toggleSortOrder 0)))))
    (gui/listen link-list :selection
                (fn [e]
                  (if (gui/selection link-list)
                    (gui/config! [copy-action remove-action] :enabled? true)
                    (gui/config! [copy-action remove-action] :enabled? false))))
    (gui/left-right-split (gui/scrollable url-list)
                          link-list-panel)))

(comment
  (def f (make-jslink-view))

  (utils/show-ui f)

  )

;;;; extension info
(def reg (scripts/reg-script! :jslink
                              {:name (tr :script-name)
                               :version "0.1.2"
                               :min-burp-clj-version "0.4.11"
                               :context-menu {:jslink/context-menu (jslink-menu)}
                               :scanner-check {:jslink/jslink-scan (jslink-issue-check)}
                               :tab {:jslink/result-tab
                                     {:captain "JS Links"
                                      :view (make-jslink-view)}}}))

;;;;;; tests
(comment
  ;; test parse
  (defn test-parse []
    (assert (= (parse-links "\"http://example.com\"") ["http://example.com"]))
    (assert (= (parse-links "\"smb://example.com\"") ["smb://example.com"]))
    (assert (= (parse-links "\"https://www.example.co.us\"") ["https://www.example.co.us"]))
    (assert (= (parse-links "\"/path/to/file\"") ["/path/to/file"]))
    (assert (= (parse-links "\"../path/to/file\"") ["../path/to/file"]))
    (assert (= (parse-links "\"./path/to/file\"") ["./path/to/file"]))
    (assert (= (parse-links "\"/user/create.action?user=Test\"") ["/user/create.action?user=Test"]))
    (assert (= (parse-links "\"/api/create.php?user=test&pass=test#home\"") ["/api/create.php?user=test&pass=test#home"]))
    (assert (nil? (parse-links "\"/wrong/file/test<>b\"")))

    (assert (= (parse-links "\"api/create.php\"") ["api/create.php"]))
    (assert (= (parse-links "\"api/create.php?user=test\"") ["api/create.php?user=test"]))
    (assert (= (parse-links "\"api/create.php?user=test&pass=test\"") ["api/create.php?user=test&pass=test"]))
    (assert (= (parse-links "\"api/create.php?user=test#home\"") ["api/create.php?user=test#home"]))
    (assert (= (parse-links "\"user/create.action?user=Test\"") ["user/create.action?user=Test"]))
    (assert (= (parse-links "\"user/create.notaext?user=Test\"") nil))
    (assert (= (parse-links "\"/path/to/file\"") ["/path/to/file"]))
    (assert (= (parse-links "\"../path/to/file\"") ["../path/to/file"]))
    (assert (= (parse-links "\"./path/to/file\"") ["./path/to/file"]))
    (assert (= (parse-links "\"/wrong/file/test<>b\"") nil))

    (assert (= (parse-links "\"api/user\"") ["api/user"]))
    (assert (= (parse-links "\"v1/create\"") ["v1/create"]))
    (assert (= (parse-links "\"api/v1/user/2\"") ["api/v1/user/2"]))
    (assert (= (parse-links "\"api/v1/search?text=Test Hello\"") ["api/v1/search?text=Test Hello"]))
    (assert (= (parse-links "\"test_1.json\"") ["test_1.json"]))
    (assert (= (parse-links "\"test2.aspx?arg1=tmp1+tmp2&arg2=tmp3\"") ["test2.aspx?arg1=tmp1+tmp2&arg2=tmp3"]))
    (assert (= (parse-links "\"addUser.action\"") ["addUser.action"]))
    (assert (= (parse-links "\"main.js\"") ["main.js"]))
    (assert (= (parse-links "\"index.html\"") ["index.html"]))
    (assert (= (parse-links "\"robots.txt\"") ["robots.txt"]))
    (assert (= (parse-links "\"users.xml\"") ["users.xml"]))
    (assert (= (parse-links "\"UserModel.name\"") nil))
    (assert (= (set (parse-links "href=\"http://example.com\";href=\"/api/create.php\""))
               (set ["http://example.com", "/api/create.php"])))
    )

  (test-parse)

  )

