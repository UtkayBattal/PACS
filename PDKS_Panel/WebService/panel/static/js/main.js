// Flash mesajlarını belirli süre sonra otomatik kapat
document.addEventListener("DOMContentLoaded", function () {
  // Başarılı kullanıcı ekleme mesajları için 10 saniye
  setTimeout(function () {
    var successAlerts = document.querySelectorAll(
      ".alert-success:not(.alert-no-dismiss)"
    );
    successAlerts.forEach(function (alert) {
      if (alert.innerHTML.includes("Kullanıcı başarıyla eklendi")) {
        // ID bilgisini içeren başarı mesajları için daha uzun gösterme süresi
      } else {
        var closeBtn = alert.querySelector(".btn-close");
        if (closeBtn) {
          closeBtn.click();
        }
      }
    });
  }, 5000);

  // Başarılı kullanıcı ekleme mesajları için 10 saniye sonra kapat
  setTimeout(function () {
    var successAlerts = document.querySelectorAll(
      ".alert-success:not(.alert-no-dismiss)"
    );
    successAlerts.forEach(function (alert) {
      if (alert.innerHTML.includes("Kullanıcı başarıyla eklendi")) {
        var closeBtn = alert.querySelector(".btn-close");
        if (closeBtn) {
          closeBtn.click();
        }
      }
    });
  }, 10000);

  // Diğer tüm mesajlar için 5 saniye
  setTimeout(function () {
    var otherAlerts = document.querySelectorAll(
      ".alert:not(.alert-success):not(.alert-no-dismiss)"
    );
    otherAlerts.forEach(function (alert) {
      var closeBtn = alert.querySelector(".btn-close");
      if (closeBtn) {
        closeBtn.click();
      }
    });
  }, 5000);
}); 