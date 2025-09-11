;;; gitleaks.el --- Simple gitleaks elisp wrapper -*- lexical-binding: t; -*-

;; Copyright (C) 2025 yqrashawn
;;
;; Author: yqrashawn <namy.19@gmail.com>
;; Maintainer: yqrashawn <namy.19@gmail.com>
;; Version: 0.0.1
;; Keywords: security tools
;; URL: https://github.com/yqrashawn/gitleaks.el
;; Package-Requires: ((emacs "25.1") (seq "2.24"))
;;
;; This file is not part of GNU Emacs.

;;; Commentary:

;; A elisp wrapper for gitleaks.
;; It provides functions to do gitleaks scan on input string or buffer.

;;; Code:

(require 'json)
(require 'seq)

;;; Customization

(defgroup gitleaks nil
  "Interface to gitleaks secret scanner."
  :prefix "gitleaks-"
  :group 'tools)

(defcustom gitleaks-executable "gitleaks"
  "Path to the gitleaks executable."
  :type 'string
  :group 'gitleaks)

(defcustom gitleaks-config-file nil
  "Path to gitleaks configuration file.

If nil, gitleaks will use its default configuration."
  :type '(choice (const :tag "Use default config" nil)
          (file :tag "Config file path"))
  :group 'gitleaks)

(defcustom gitleaks-baseline-file nil
  "Path to gitleaks baseline file.

Findings in the baseline will be ignored in subsequent scans."
  :type '(choice (const :tag "No baseline" nil)
          (file :tag "Baseline file path"))
  :group 'gitleaks)

(defcustom gitleaks-report-format "json"
  "Default report format for gitleaks output."
  :type '(choice (const "json")
          (const "csv")
          (const "junit")
          (const "sarif"))
  :group 'gitleaks)

(defcustom gitleaks-default-flags (list "--redact=100")
  "Additional command line flags to pass to gitleaks."
  :type '(repeat string)
  :group 'gitleaks)

(defcustom gitleaks-buffer-name "*gitleaks*"
  "Name of the buffer to display gitleaks results."
  :type 'string
  :group 'gitleaks)

;;; Internal variables

(defvar gitleaks--last-command nil
  "The last gitleaks command that was executed.")

(defvar gitleaks--last-results nil
  "The results from the last gitleaks scan.")

(defvar gitleaks--redact-command nil
  "If current user command is redact command")

;;; Utility functions

(defun gitleaks--point-at-line-col (line col)
  "Return point at LINE and COL (both 1-based)."
  (save-excursion
    (goto-char (point-min))
    (forward-line (1- line))
    (move-to-column (1- col))
    (point)))

(defun gitleaks--executable ()
  "Return the gitleaks executable path, checking if it exists."
  (let ((exe (executable-find gitleaks-executable)))
    (unless exe
      (error "Gitleaks executable not found: %s" gitleaks-executable))
    exe))

(defun gitleaks--build-command (subcommand target &optional extra-args)
  "Build a gitleaks command with SUBCOMMAND and TARGET.

EXTRA-ARGS is a list of additional arguments to pass to gitleaks."
  (let ((cmd (list (gitleaks--executable) subcommand "--no-banner" "--no-color")))
    ;; Add configuration file if specified
    (when gitleaks-config-file
      (setq cmd (append cmd (list "--config" (expand-file-name gitleaks-config-file)))))
    
    ;; Add baseline file if specified
    (when gitleaks-baseline-file
      (setq cmd (append cmd (list "--baseline-path" (expand-file-name gitleaks-baseline-file)))))
    
    ;; Add report format
    (setq cmd (append cmd (list "--report-format" gitleaks-report-format)))
    
    ;; Add default flags
    (when gitleaks-default-flags
      (setq cmd (append cmd gitleaks-default-flags)))
    
    ;; Add extra arguments
    (when extra-args
      (setq cmd (append cmd extra-args)))
    
    ;; Add target
    (when target
      (setq cmd (append cmd (list target))))

    (when gitleaks--redact-command
      (setq cmd
            (seq-remove
             (lambda (s) (string-prefix-p "--redact" s))
             cmd)))

    cmd))

(defun gitleaks--wait-process (proc &optional timeout)
  "Block until PROC exits or TIMEOUT seconds passes. Return exit code or TIMEOUT."
  (let ((deadline (and timeout (+ (float-time) timeout))))
    (while (and (process-live-p proc)
                (or (null deadline) (< (float-time) deadline)))
      (accept-process-output proc 0.1))
    (if (process-live-p proc) 'timeout (process-exit-status proc))))

(defun gitleaks--run-command (command &optional callback)
  "Run gitleaks COMMAND and optionally call CALLBACK with results.

Returns the process object."
  (let* ((buffer-name (format " *gitleaks-process-%s*" (format-time-string "%s")))
         (process-buffer (get-buffer-create buffer-name))
         (default-directory (or default-directory "~/")))
    (setq gitleaks--last-command command)
    (with-current-buffer process-buffer
      (erase-buffer))
    (let ((proc (apply #'start-process "gitleaks" process-buffer command)))
      (when callback
        (set-process-sentinel
         proc
         (lambda (process event)
           (when (memq (process-status process) '(exit signal))
             (funcall callback process))
           (kill-buffer process-buffer))))
      proc)))

(defun gitleaks--parse-json-results (json-string)
  "Parse gitleaks JSON results from JSON-STRING."
  (when (and json-string (not (string-empty-p (string-trim json-string))))
    (condition-case err
        (let ((results (json-read-from-string json-string)))
          ;; Convert vector to list if needed
          (if (vectorp results)
              (append results nil)
            results))
      (error
       (message "Failed to parse gitleaks JSON output: %s" err)
       nil))))

(defun gitleaks--format-finding (finding)
  "Format a single gitleaks FINDING for display."
  (let-alist finding
    (format "File: %s:%d\nRule: %s\nSecret: %s\nDescription: %s\nCommit: %s\nAuthor: %s\nDate: %s\n%s\n"
            (or .RuleID "<unknown>")
            (or .Description "<no description>")
            (or .File "<unknown>")
            (or .StartLine 0)
            (or .EndLine 0)
            (or .StartColumn 0)
            (or .EndColumn 0)
            (or .Match "<redacted>")
            (or .Secret "<redacted>")
            (or .Commit "<no commit>")
            (or .Author "<unknown>")
            (or .Date "<unknown>")
            (make-string 80 ?-))))

(defun gitleaks--display-results (results)
  "Display gitleaks RESULTS in a buffer."
  (let ((buffer (get-buffer-create gitleaks-buffer-name)))
    (with-current-buffer buffer
      (let ((inhibit-read-only t))
        (erase-buffer)
        (if results
            (progn
              (insert (format "Gitleaks found %d potential secret(s):\n\n" (length results)))
              (dolist (finding results)
                (insert (gitleaks--format-finding finding)))
              (insert "\n\nScan completed.\n"))
          (insert "No secrets detected.\n\nScan completed.\n"))
        (goto-char (point-min))
        (view-mode 1)))
    (display-buffer buffer)))

(defun gitleaks--redact-string-with-findings (string findings)
  "Redact secrets in STRING based on FINDINGS.

Returns a new string with secrets replaced by =REDACTED=."
  (if (not findings)
      string
    (let ((result string))
      (dolist (finding findings)
        (let-alist finding
          (when .Secret
            (setq result (replace-regexp-in-string 
                          (regexp-quote .Secret)
                          "==REDACTED=="
                          result)))))
      result)))

;;; Core scanning functions

(defun gitleaks-scan-string (string)
  "Scan STRING for secrets using gitleaks.

Returns a list of findings or nil if no secrets found."
  (let ((temp-file (make-temp-file "gitleaks-scan-" nil ".txt")))
    (unwind-protect
        (progn
          (with-temp-file temp-file
            (insert string))
          (gitleaks-scan-file temp-file))
      (delete-file temp-file))))

(defun gitleaks-scan-buffer (&optional buffer)
  "Scan BUFFER (or current buffer) for secrets using gitleaks.

Returns a list of findings or nil if no secrets found."
  (interactive)
  (let ((buffer (or buffer (current-buffer))))
    (with-current-buffer buffer
      (let ((content (buffer-string)))
        (if (string-empty-p (string-trim content))
            (progn
              (message "Buffer is empty")
              nil)
          (let ((results (gitleaks-scan-string content)))
            (setq gitleaks--last-results results)
            (when (called-interactively-p 'interactive)
              (gitleaks--display-results results)
              (message "Gitleaks scan completed. Found %d potential secret(s)." 
                       (length (or results nil))))
            results))))))

(defun gitleaks-scan-file (file)
  "Scan FILE for secrets using gitleaks.

Returns a list of findings or nil if no secrets found."
  (interactive "fFile to scan: ")
  (unless (file-exists-p file)
    (error "File does not exist: %s" file))
  (let* ((temp-output (make-temp-file "gitleaks-output-" nil ".json"))
         (command (gitleaks--build-command "dir" 
                                           (expand-file-name file)
                                           (list "--report-path" temp-output)))
         (process (gitleaks--run-command command))
         results)
    (gitleaks--wait-process process)
    (unwind-protect
        (when (file-exists-p temp-output)
          (let ((json-content (with-temp-buffer
                                (insert-file-contents temp-output)
                                (buffer-string))))
            (setq results (gitleaks--parse-json-results json-content))))
      (when (file-exists-p temp-output)
        (delete-file temp-output)))
    (setq gitleaks--last-results results)
    (when (called-interactively-p 'interactive)
      (gitleaks--display-results results)
      (message "Gitleaks scan completed. Found %d potential secret(s)." 
               (length (or results nil))))
    results))

(defun gitleaks-scan-directory (directory)
  "Scan DIRECTORY for secrets using gitleaks.

Returns a list of findings or nil if no secrets found."
  (interactive "DDirectory to scan: ")
  (unless (file-directory-p directory)
    (error "Directory does not exist: %s" directory))
  (let* ((temp-output (make-temp-file "gitleaks-output-" nil ".json"))
         (command (gitleaks--build-command "dir"
                                           (expand-file-name directory)
                                           (list "--report-path" temp-output)))
         (process (gitleaks--run-command command))
         results)
    (gitleaks--wait-process process)
    (unwind-protect
        (when (file-exists-p temp-output)
          (let ((json-content (with-temp-buffer
                                (insert-file-contents temp-output)
                                (buffer-string))))
            (setq results (gitleaks--parse-json-results json-content))))
      (when (file-exists-p temp-output)
        (delete-file temp-output)))
    (setq gitleaks--last-results results)
    (when (called-interactively-p 'interactive)
      (gitleaks--display-results results)
      (message "Gitleaks scan completed. Found %d potential secret(s)."
               (length (or results nil))))
    results))

(defun gitleaks-scan-git-repository (&optional repository)
  "Scan git REPOSITORY for secrets using gitleaks.

If REPOSITORY is nil, scan the current git repository.
Returns a list of findings or nil if no secrets found."
  (interactive)
  (let* ((repo-dir (or repository 
                       (and (bound-and-true-p vc-mode)
                            (vc-find-root default-directory ".git"))
                       default-directory))
         (temp-output (make-temp-file "gitleaks-output-" nil ".json"))
         (command (gitleaks--build-command "git" 
                                           (expand-file-name repo-dir)
                                           (list "--report-path" temp-output)))
         (process (gitleaks--run-command command))
         results)
    (gitleaks--wait-process process)
    (unwind-protect
        (when (file-exists-p temp-output)
          (let ((json-content (with-temp-buffer
                                (insert-file-contents temp-output)
                                (buffer-string))))
            (setq results (gitleaks--parse-json-results json-content))))
      (when (file-exists-p temp-output)
        (delete-file temp-output)))
    (setq gitleaks--last-results results)
    (when (called-interactively-p 'interactive)
      (gitleaks--display-results results)
      (message "Gitleaks scan completed. Found %d potential secret(s)." 
               (length (or results nil))))
    results))

;;; Predicate functions

(defun gitleaks-string-p (string)
  "Return non-nil if STRING contains secrets detected by gitleaks."
  (let ((results (gitleaks-scan-string string)))
    (and results (> (length results) 0))))

(defun gitleaks-buffer-p (&optional buffer)
  "Return non-nil if BUFFER (or current buffer) contains secrets."
  (let ((buffer (or buffer (current-buffer))))
    (with-current-buffer buffer
      (let ((content (buffer-string)))
        (if (string-empty-p (string-trim content))
            nil
          (gitleaks-string-p content))))))

;;; Redaction functions

(defun gitleaks-redact-string (string)
  "Scan STRING for secrets and return a redacted copy.

All detected secrets are replaced with =REDACTED=."
  (let* ((gitleaks--redact-command t)
         (findings (gitleaks-scan-string string)))
    (gitleaks--redact-string-with-findings string findings)))

(defun gitleaks-redact-buffer (&optional buffer)
  "Scan BUFFER for secrets and return a new buffer with redacted content.

If BUFFER is nil, use the current buffer.
All detected secrets are replaced with =REDACTED=."
  (interactive)
  (let* ((source-buffer (or buffer (current-buffer)))
         (source-name (buffer-name source-buffer))
         (redacted-buffer-name (format "*gitleaks-redacted-%s*" source-name))
         (gitleaks--redact-command t))
    (with-current-buffer source-buffer
      (let* ((content (buffer-string))
             (findings (gitleaks-scan-string content))
             (redacted-content (gitleaks--redact-string-with-findings content findings))
             (redacted-buffer (get-buffer-create redacted-buffer-name)))
        (with-current-buffer redacted-buffer
          (erase-buffer)
          (insert redacted-content)
          (goto-char (point-min))
          (when (called-interactively-p 'interactive)
            (display-buffer redacted-buffer)
            (message "Created redacted buffer: %s (found %d secret(s))"
                     redacted-buffer-name (length (or findings nil)))))
        redacted-buffer))))

;;; Interactive commands

;;;###autoload
(defun gitleaks-scan-current-file ()
  "Scan the current file for secrets."
  (interactive)
  (let ((file (buffer-file-name)))
    (if file
        (gitleaks-scan-file file)
      (error "Current buffer is not associated with a file"))))

;;;###autoload
(defun gitleaks-scan-project ()
  "Scan the current project for secrets."
  (interactive)
  (let ((project-root (or (and (fboundp 'project-root)
                               (project-current)
                               (project-root (project-current)))
                          (and (bound-and-true-p vc-mode)
                               (vc-find-root default-directory ".git"))
                          default-directory)))
    (gitleaks-scan-directory project-root)))

;;;###autoload
(defun gitleaks-scan-region (start end)
  "Scan the current region for secrets."
  (interactive "r")
  (if (use-region-p)
      (let ((content (buffer-substring-no-properties start end)))
        (let ((results (gitleaks-scan-string content)))
          (gitleaks--display-results results)
          (message "Gitleaks scan completed. Found %d potential secret(s)." 
                   (length (or results nil)))))
    (error "No region selected")))

;;;###autoload
(defun gitleaks-show-last-results ()
  "Show the results from the last gitleaks scan."
  (interactive)
  (if gitleaks--last-results
      (gitleaks--display-results gitleaks--last-results)
    (message "No previous gitleaks results available")))

;;; Utility commands

(defun gitleaks-version ()
  "Show gitleaks version."
  (interactive)
  (let ((process (gitleaks--run-command
                  (list (gitleaks--executable) "version")
                  (lambda (proc)
                    (with-current-buffer (process-buffer proc)
                      (message "Gitleaks version: %s"
                               (string-trim (buffer-string))))))))
    (unless (called-interactively-p 'interactive)
      (gitleaks--wait-process process)
      (with-current-buffer (process-buffer process)
        (string-trim (buffer-string))))))

(defun gitleaks-generate-baseline (&optional output-file)
  "Generate a baseline file for future scans.

If OUTPUT-FILE is provided, save the baseline to that file.
Otherwise, prompt for a file location."
  (interactive)
  (let* ((output (or output-file
                     (read-file-name "Save baseline to: " nil "gitleaks-baseline.json")))
         (project-root (or (and (fboundp 'project-root)
                                (project-current)
                                (project-root (project-current)))
                           (and (bound-and-true-p vc-mode)
                                (vc-find-root default-directory ".git"))
                           default-directory))
         (command (gitleaks--build-command "git" 
                                           project-root
                                           (list "--report-path" (expand-file-name output))))
         (process (gitleaks--run-command command)))
    (gitleaks--wait-process process)
    (if (file-exists-p output)
        (message "Baseline saved to: %s" output)
      (message "Failed to generate baseline"))))

(provide 'gitleaks)
;;; gitleaks.el ends here
