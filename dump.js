  <script>
    document.addEventListener('DOMContentLoaded', function () {
      const selectedDates = new Set();
      const calendarEl = document.getElementById('calendar');
      const sessionDaysInput = document.getElementById('session_days');

      const calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: 'dayGridMonth',
        selectable: true,
        selectMirror: true,
        select: function(info) {
          const dateStr = info.startStr + "T00:00"; // add dummy time for Go
          if (selectedDates.has(dateStr)) {
            selectedDates.delete(dateStr);
          } else {
            selectedDates.add(dateStr);
          }
          updateHighlights();
        },
        dayMaxEvents: true,
        events: function(info, successCallback) {
          const eventArray = Array.from(selectedDates).map(date => ({
            title: 'Selected',
            start: date,
            allDay: true
          }));
          successCallback(eventArray);
        }
      });

      function updateHighlights() {
        sessionDaysInput.value = Array.from(selectedDates).join(',');
        calendar.refetchEvents();
      }

      document.getElementById('minisForm').addEventListener('submit', function (e) {
        e.preventDefault();

        const formData = new URLSearchParams(new FormData(this));

        fetch('/create/minis_session', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: formData
        })
        .then(res => {
          if (res.ok) {
            alert('Minis session created!');
            window.location.reload(); // Or redirect
          } else {
            res.text().then(msg => alert('Error: ' + msg));
          }
        });
      });

      calendar.render();
    });
  </script>
