<template>
  <nav class="navbar navbar-expand-lg navbar-light">
    <div class="container-fluid">
      <h4>{{routeName}}</h4>
      <button class="navbar-toggler navbar-burger"
              type="button"
              @click="toggleSidebar"
              :aria-expanded="$sidebar.showSidebar"
              aria-label="Toggle navigation">
        <span class="navbar-toggler-bar"></span>
        <span class="navbar-toggler-bar"></span>
        <span class="navbar-toggler-bar"></span>
      </button>
      <div class="collapse navbar-collapse">
        <ul class="navbar-nav ml-auto">
          <drop-down class="nav-item"
                     title="Notifications"
                     title-classes="nav-link"
                     icon="ti-bell">
            <a class="dropdown-item" href="#/notifications">Notification 1</a>
            <a class="dropdown-item" href="#/notofications">Notification 2</a>
            <a class="dropdown-item" href="#/notifications">Notification 3</a>
            <a class="dropdown-item" href="#/notifications">Notification 4</a>
            <a class="dropdown-item" href="#/notifications">Another notification</a>
          </drop-down>
          <li class="nav-item">
            <a href="#" class="nav-link">
              <i class="ti-user"></i>
              <p>Profile</p>
            </a>
          </li>
          <li class="nav-item">
            <a href="#" class="nav-link">
              <i class="ti-settings"></i>
              <p>
                Settings
              </p>
            </a>
          </li>
        </ul>
      </div>
    </div></nav>
</template>
<script>
export default {
  computed: {
    routeName() {
      const { name } = this.$route;
      return this.capitalizeFirstLetter(name);
    }
  },
  data() {
    return {
      activeNotifications: false
    };
  },
  methods: {
    capitalizeFirstLetter(string) {
      return string.charAt(0).toUpperCase() + string.slice(1);
    },
    toggleNotificationDropDown() {
      this.activeNotifications = !this.activeNotifications;
    },
    closeDropDown() {
      this.activeNotifications = false;
    },
    toggleSidebar() {
      this.$sidebar.displaySidebar(!this.$sidebar.showSidebar);
    },
    hideSidebar() {
      this.$sidebar.displaySidebar(false);
    }
  }
};
</script>
<style>
</style>
