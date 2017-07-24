$(document).ready(function() {
  var $sidebar = $('.sidebar');
  var $sidebarMenu = $sidebar.children('ul');
  var $sidebarBtn = $sidebar.find('button');
  var $menuLi = $sidebar.find('.menu > li');

  $sidebarBtn.on('click', function (e) {
    $sidebarMenu.toggleClass('hidden');
  });

  $menuLi.on('click', function (e) {
    $innerUl = $(this).find('ul');

    $menuLi.each(function () {
      $(this).removeClass('active');
    });

    $(this).addClass('active');
    $innerUl.slideToggle();
    $(this).siblings().find('ul').slideUp();
    return false;
  });
});
