(ns ip-loc
  (:require [seesaw.core :as gui]
            [clojure.string :as str]
            [taoensso.timbre :as log]
            [burp-clj.utils :as utils]
            [burp-clj.message-editor :as message-editor]
            [burp-clj.extender :as extender]
            [burp-clj.scripts :as scripts]
            [burp-clj.helper :as helper])
  (:import [burp IMessageEditorTab]))


(utils/add-dep '[[ntestoc3/netlib "0.3.4-SNAPSHOT"]])
(require '[netlib.qqwry :as qqwry])

(defn parent-until [ui-comp parent-instance]
  (when-let [parent (.getParent ui-comp)]
    (if (instance? parent-instance parent)
      parent
      (recur parent parent-instance))))

(comment

  (def sp (parent-until @comp javax.swing.JSplitPane))

  (def tp (.getTopComponent sp ))

  (.getSuperclass (class tp  ))
  (.getCorner tp  javax.swing.ScrollPaneConstants/UPPER_TRAILING_CORNER)
  (.getCorner tp  javax.swing.ScrollPaneConstants/UPPER_RIGHT_CORNER)

  (.getSuperclass (class (first (.getComponents (first tps)))))

  (.getColumnCount t1)

  (def model (.getModel t1))

  (.getSuperclass (.getSuperclass (class model )))
  ;; javax.swing.table.AbstractTableModel
  ;; 无法动态添加列

  (doseq [i (range (.getColumnCount model))]
    (prn (.getColumnName model i )))

  (defn find-column-idx [model column-name]
    (->> (.getColumnCount model)
         range
         (filter #(= column-name
                     (.getColumnName model %1)))
         first
         ))

  (def ip-idx (find-column-idx model "IP"))
  (def ip-idx (.findColumn model "IP"))

  (def ips (->> (.getRowCount model)
                range
                (map #(.getValueAt model %1 ip-idx))
                ))
  (def ip-locs (map #(let [{:keys [county area]} (qqwry/get-location %)]
                       (str county " -- " area))
                    ips))


  )

(def comp (atom nil))

(defn make-tab [caption]
  (reify IMessageEditorTab
    (getMessage [this]
      (log/info :ip-loc-tab "getMessage")
      nil)
    (getSelectedData [this] nil)
    (getTabCaption [this]
      caption)
    (getUiComponent [this]
      (let [lbl (gui/label :text caption)]
        (reset! comp lbl)
        lbl))
    (isEnabled [this content is-req]
      (log/info :ip-log-tab "enabled?" caption
                ;; "content:" (helper/bytes->str content)
                "req?:"is-req)
      (not (nil? caption)))
    (isModified [this] false)
    (setMessage [this content is-req]
      (log/info :ip-log-tab "setMessage")
      )))


(defn make-ip-tab
  [msg editable]
  (let [ip (-> (.getHttpService msg)
               (.getHost)
               qqwry/get-location)
        title (str (:county ip) " -- " (:area ip))]
    (log/info :make-ip-tab title)
    (make-tab title)))

(def reg (scripts/reg-script! :ip-location
                              {:name "show ip location"
                               :version "0.0.1"
                               :min-burp-clj-version "0.1.0"
                               :message-editor-tab {:ip-loc
                                                    ;; proxy history里只会req response各创建一次
                                                    (message-editor/make-message-editor-tab
                                                     make-ip-tab)}}))
