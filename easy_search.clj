(ns easy-search
  "方便在repeater中搜索，在request或response中选中文本，
  然后右键，自动在response中搜索选中的文本"
  (:require [seesaw.core :as gui]
            [clojure.java.browse :refer [browse-url]]
            [clojure.string :as str]
            [taoensso.timbre :as log]
            [burp-clj.context-menu :as context-menu]
            [burp-clj.extender :as extender]
            [burp-clj.scripts :as scripts]
            [burp-clj.helper :as helper])
  (:import java.awt.event.KeyEvent))

(def menu-context #{:message-editor-request
                    :message-editor-response
                    :message-viewer-request
                    :message-viewer-response})

(defn find-first-parent
  [ui-comp parent-class]
  (if (instance? parent-class ui-comp)
    ui-comp
    (recur (.getParent ui-comp) parent-class)))

(defn key-enter [comp keycode]
  (doto comp
    (.dispatchEvent (KeyEvent. comp
                               KeyEvent/KEY_PRESSED
                               (System/currentTimeMillis)
                               0
                               keycode
                               (char keycode)) )
    (.dispatchEvent (KeyEvent. comp
                               KeyEvent/KEY_RELEASED
                               (System/currentTimeMillis)
                               0
                               keycode
                               (char keycode)))))

(defn easy-search-menu []
  (context-menu/make-context-menu
   menu-context
   (fn [invocation]
     ;; 只针对repeater
     (when (= :repeater  (-> (.getToolFlag invocation)
                             helper/tool-type-inv))
       (let [txt (context-menu/get-selected-text invocation)]
         (when-not (empty? txt)
           (-> (.getInputEvent invocation)
               ;; 查找搜索框
               (gui/to-widget)
               (find-first-parent javax.swing.JSplitPane)
               (.getRightComponent)
               (gui/select [:<javax.swing.JTextField>])
               (as-> $
                   (doseq [t $]
                     ;; 设置搜索框的值
                     (when (gui/config t :editable?)
                       (gui/text! t txt)
                       (key-enter t KeyEvent/VK_ENTER)))))))))))


(def reg (scripts/reg-script! :easy-search
                              {:name "easy search text in repeater"
                               :version "0.0.1"
                               :min-burp-clj-version "0.4.3"
                               :context-menu {:easy-search (easy-search-menu)}}))
