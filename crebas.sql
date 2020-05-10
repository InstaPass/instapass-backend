/*==============================================================*/
/* DBMS name:      MySQL 5.0                                    */
/* Created on:     2020/4/25 16:10:25                           */
/*==============================================================*/


drop table if exists Admin_user;

drop table if exists Anno;

drop table if exists Dweller_group;

drop table if exists Dweller_user;

drop table if exists Guard_user;

drop table if exists io_info;

/*==============================================================*/
/* Table: Admin_user                                            */
/*==============================================================*/
create table Admin_user
(
   admin_id             char(256) not null,
   admin_password       char(256),
   primary key (admin_id)
);

/*==============================================================*/
/* Table: Anno                                                  */
/*==============================================================*/
create table Anno
(
   anno_id              int not null,
   admin_id             char(256),
   message              longtext,
   primary key (anno_id)
);

/*==============================================================*/
/* Table: Dweller_group                                         */
/*==============================================================*/
create table Dweller_group
(
   group_id             int not null,
   io_num               int,
   primary key (group_id)
);

/*==============================================================*/
/* Table: Dweller_user                                          */
/*==============================================================*/
create table Dweller_user
(
   Dweller_ID           char(32) not null,
   group_id             int,
   name                 char(256),
   build                char(256),
   auth                 int,
   primary key (Dweller_ID)
);

/*==============================================================*/
/* Table: Guard_user                                            */
/*==============================================================*/
create table Guard_user
(
   guard_id             char(256) not null,
   guard_password       char(256),
   primary key (guard_id)
);

/*==============================================================*/
/* Table: io_info                                               */
/*==============================================================*/
create table io_info
(
   io_info_id           int not null,
   Dweller_ID           char(32) not null,
   guard_id             char(256) not null,
   gate                 char(256),
   time                 datetime,
   temp                 float,
   left_num             int,
   primary key (io_info_id, Dweller_ID, guard_id)
);

alter table Anno add constraint FK_admin_anno foreign key (admin_id)
      references Admin_user (admin_id) on delete restrict on update restrict;

alter table Dweller_user add constraint FK_group_owner foreign key (group_id)
      references Dweller_group (group_id) on delete restrict on update restrict;

alter table io_info add constraint FK_io_info foreign key (Dweller_ID)
      references Dweller_user (Dweller_ID) on delete restrict on update restrict;

alter table io_info add constraint FK_io_info2 foreign key (guard_id)
      references Guard_user (guard_id) on delete restrict on update restrict;

